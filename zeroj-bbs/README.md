# zeroj-bbs

CFRG BBS draft-10 signatures and selective disclosure for ZeroJ.

This module implements the BLS12-381 ciphersuites from
`draft-irtf-cfrg-bbs-signatures-10`:

```text
BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_
BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_
```

Implemented operations:

- `KeyGen`
- `SkToPk`
- `Sign`
- `Verify`
- `ProofGen`
- `ProofVerify`

The implementation is vector-tested against the official draft-10 SHA-256 and
SHAKE-256 vectors for key generation, public-key derivation, message scalar
mapping, generator derivation, signatures, proof generation, proof verification,
hash-to-scalar, and mocked random scalars. The tests cover the draft fixture JSON
for both ciphersuites: 10 signature cases and 15 proof cases per ciphersuite.

## Basic Use

```java
var service = BbsService.pureJava();

// Optional SHAKE-256 ciphersuite:
var shakeService = BbsService.pureJava(BbsCiphersuite.BLS12381_SHAKE256);

// Optional explicit BLS12-381 provider selection:
var serviceWithBlsProvider = BbsService.withBlsProvider(
        BbsCiphersuite.BLS12381_SHA256,
        blsProvider);

var keyPair = service.keyPair(keyMaterial, keyInfo);
var signature = service.sign(keyPair.secretKey(), keyPair.publicKey(), messages, header);

boolean signatureValid = service.verify(keyPair.publicKey(), signature, messages, header);

var presentation = service.derivePresentation(
        keyPair.publicKey(),
        signature,
        messages,
        header,
        presentationHeader,
        new int[]{0, 2});

boolean proofValid = service.verifyPresentation(keyPair.publicKey(), presentation);
```

`messages`, `header`, and `presentationHeader` are byte arrays. Revealed indexes
are zero-based and must be strictly ascending.

## Presentation Encoding

`BbsPresentationCodec` wraps draft-compatible proof bytes in a small
deterministic CBOR envelope:

```java
byte[] cbor = BbsPresentationCodec.encode(presentation);
BbsPresentation decoded = BbsPresentationCodec.decode(cbor);
```

Use proof format:

```text
bbs-cfrg-draft10-presentation-cbor-v1
```

## On-Chain Verification (Cardano)

`com.bloxbean.cardano.zeroj.bbs.cardano.BbsToCardano` bridges a presentation to a
Cardano on-chain BBS verifier. It is plain off-chain Java (runs in the application
JVM, no Julc/Plutus dependency) and produces the two things an on-chain validator
needs:

```java
// issuer verification material → validator @Param bytes
var params = BbsToCardano.verifierParams(issuerPublicKey, header, messageCount);
// a presentation flattened → redeemer fields (points, scalars, revealed messages, ph)
var proof  = BbsToCardano.onChainProof(presentation);
```

The matching on-chain gadget — a native Plutus V3 BBS `ProofVerify` that the
Cardano ledger runs itself — is `BbsProofVerify` (with the `BbsHashToScalar`
primitive) in the **`zeroj-onchain-julc`** module. Together they let a validator
verify a BBS selective-disclosure proof entirely on-chain. See that module's
README for a worked validator; `zeroj-usecases` reusable-kyc is a full example
(lock a voucher, claim it only against a valid on-chain-verified presentation).

## ZeroJ Verifier

`BbsZkVerifier` verifies `ZkProofEnvelope` values with:

- `ProofSystemId.BBS`
- `CurveId.BLS12_381`
- `proofFormat = bbs-cfrg-draft10-presentation-cbor-v1`
- verification material `vkBytes = issuer BBS public key`

The verifier checks cryptographic validity only. Issuer trust, schema checks,
expiration, revocation, holder binding, and disclosure policy remain application
policy.

## WASM Provider

`zeroj-bbs-wasm` provides an explicit opt-in provider:

```java
var provider = com.bloxbean.cardano.zeroj.bbs.wasm.WasmBbsProvider.createDefault();
var service = new BbsService(provider);
```

It uses the same BBS draft implementation with BLS12-381 operations backed by
the Rust/Chicory `zeroj-bls12381-wasm` module.

## Native blst BLS Provider

`zeroj-blst` exposes a native-backed BLS12-381 provider that can be selected
without changing the BBS API:

```java
var bls = com.bloxbean.cardano.zeroj.blst.BlstBls12381Provider.createDefault();
var service = BbsService.withBlsProvider(BbsCiphersuite.BLS12381_SHA256, bls);
```

The `zeroj-bbs` conformance tests run the same official draft-10 signature and
proof vectors against the pure Java, WASM, and blst BLS providers.

## Production Hardening

- SHA-256 and SHAKE-256 ciphersuites are implemented and pass official
  draft-10 fixture vectors.
- BBS secret-key, signature, proof-randomness, and hidden-message scalar
  multiplications go through the explicit `Bls12381Provider` secret-scalar
  boundary.
- The default pure Java BLS provider backs that boundary with fixed-schedule
  Jacobian scalar multiplication and fixed-exponent Montgomery-form scalar
  inversion, but it is not a full JVM constant-time guarantee.
- Production workloads that carry high-value BBS signing keys, proof
  randomness, or hidden-message scalars should select a native BLS provider with
  a stronger side-channel contract, such as `zeroj-blst`, via
  `BbsService.withBlsProvider(...)`.

References:

- <https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-10.txt>
- <https://github.com/decentralized-identity/bbs-signature/tree/main/tooling/fixtures/fixture_data>
