# zeroj-bls12381

Shared pure Java BLS12-381 primitives for ZeroJ.

This module contains the JVM implementation of the BLS12-381 field, curve,
pairing, hash-to-curve, and provider abstractions used by the rest of ZeroJ. It
is the zero-native-dependency foundation for Cardano-native proof systems and
BBS selective disclosure.

## What It Provides

| Area | Key Types |
|------|-----------|
| Field arithmetic | `Fp`, `Fp2`, `Fp6`, `Fp12`, `MontFp381`, `MontFr381` |
| Curve operations | `G1Point`, `G2Point`, `JacobianG1BLS381`, `JacobianG2BLS381` |
| Pairing | `BLS12381Pairing` |
| Encoding and generators | `Bls12381Codecs`, `Bls12381Generators` |
| Hashing | `Bls12381Hash`, hash-to-curve internals |
| Provider SPI | `Bls12381Provider`, `PureJavaBls12381Provider`, `Bls12381Providers` |
| G1 Pedersen commitments (experimental) | `org.zeroj.bls12381.pedersen`: `G1Pedersen`, `G1PedersenCommitment`, `G1PedersenBytesCommitment`, `G1PedersenOpening`, `G1PedersenBlinding` |
| Range proofs on G1 commitments (experimental) | `org.zeroj.bls12381.bulletproofs`: `G1RangeProver`, `G1RangeVerifier`, `G1RangeProof` |
| SHAKE128 | `Shake128` (incremental, copyable XOF) |

## Why It Is Useful

- Provides the Cardano-native BLS12-381 curve used by Plutus V3 builtins.
- Keeps core proving and verification flows available without native libraries.
- Gives BBS, PlonK, Groth16, and test code a shared primitive layer.
- Lets optional accelerators such as `zeroj-blst` and `zeroj-bls12381-wasm`
  plug into the same provider contract.

## When To Use Directly

Most applications use this module transitively through `zeroj-crypto`,
`zeroj-verifier-groth16`, `zeroj-verifier-plonk`, or `zeroj-bbs`. Depend on it
directly when implementing a protocol that needs BLS12-381 group operations,
pairings, or an explicit `Bls12381Provider`.

## Security Contract

The pure Java provider is the portable, correctness-first implementation. It is
appropriate for public-input operations such as verification, encoding,
hash-to-curve, and public scalar multiplication.

The `g1SecretScalarMul` and `g2SecretScalarMul` provider methods are the
secret-scalar boundary for protocols that need one. In this module they use
fixed-schedule Java ladders, but they are not a full JVM constant-time guarantee:
bit access, branching, point special cases, field reductions, JIT behavior, and
GC remain outside that guarantee. Production workloads that carry high-value
secrets need a provider with an audited side-channel contract. The `zeroj-blst`
provider is native, but ZeroJ has no evidence of a side-channel contract for its
binding (its secret-scalar method is its public one), so it does not lift the
offline/isolated restriction, for example for G1 Pedersen generation below.

## G1 Pedersen commitments (experimental)

`org.zeroj.bls12381.pedersen` implements the commitment profiles `pedersen-bls12-381-g1-v1`
(`C = [m]·G + [r]·H`) and `pedersen-bls12-381-g1-bytes-v1` (a commitment to exact octets), normatively
specified in [`docs/specs/pedersen-bls12-381-g1-v1.md`](../docs/specs/pedersen-bls12-381-g1-v1.md)
([ADR-0060](../docs/adr/0060-pedersen-bls12-381-g1-profiles.md)). Cardano validators open and combine
these commitments directly with the CIP-0381 builtins (`PedersenG1Lib` in `zeroj-onchain-julc`), with
no SNARK. They are not usable inside the Jubjub circuits.

```java
G1Pedersen pedersen = G1Pedersen.pureJava();           // or withProvider(provider); see the measurements
BigInteger r = G1Pedersen.randomBlinding(new SecureRandom());
G1PedersenCommitment c = pedersen.commitScalar(BigInteger.valueOf(1_000), r);   // offline/isolated
byte[] wire = c.toPointBytes();                         // 48-octet compressed point

G1PedersenCommitment received = G1PedersenCommitment.decode(wire);  // strict: subgroup, identity accepted
boolean ok = pedersen.verifyScalar(received, BigInteger.valueOf(1_000), r, 64);  // disclosed opening
G1PedersenCommitment next = received.withPublicDelta(BigInteger.valueOf(-250), 64); // opens to 750
```

- Strict decoding of the 48-octet compressed form; the identity is accepted; nothing is reduced.
- Generation runs only through the provider's secret-scalar method and is **offline/isolated only**:
  neither the pure-Java nor the blst provider is constant-time.
- Disclosed verification is variable-time (class V1): use it only where the opening is already public.
- Results of arithmetic are residues mod `q`, not balances; an opened value is public forever.
- The registry status of both profiles is recorded in
  [`commitment-profiles-v1`](../docs/specs/commitment-profiles-v1.md) §2.3. Not approved for
  value-bearing or mainnet use without external review.

## Range proofs on G1 commitments (experimental)

`org.zeroj.bls12381.bulletproofs` implements the proof protocol `bulletproof-range-bls12-381-g1-v1`:
a Bulletproof that a `pedersen-bls12-381-g1-v1` commitment `V ≠ O` hides a value in `[0, 2^n)`,
`n ∈ {16, 32, 64}`, without opening it. It is normatively specified in
[`docs/specs/bulletproof-range-bls12-381-g1-v1.md`](../docs/specs/bulletproof-range-bls12-381-g1-v1.md)
([ADR-0061](../docs/adr/0061-bulletproof-range-proofs-bls12-381-g1.md)). There is no trusted setup.
The transcript is the CFRG `draft-irtf-cfrg-fiat-shamir-03` SHAKE128 duplex sponge with the
`sigma-proofs_Shake128_BLS12381` codecs.

```java
byte[] ctx = "https://example.com/payroll/v1".getBytes(StandardCharsets.US_ASCII); // your app's namespace
G1RangeProof proof = G1RangeProver.pureJava()                          // offline/isolated only
        .prove(G1PedersenOpening.of(amount, blinding), 64, ctx);
byte[] wire = proof.toBytes();                                         // 928 octets at n = 64

boolean inRange = G1RangeVerifier.pureJava()                           // or withProvider(provider)
        .verify(commitmentBytes, wire, 64, ctx);                       // n and ctx from YOUR configuration
```

- **`n` and `ctx` are the verifier's configuration**, never read from the proof. `ctx` (1 to 1,024
  octets) must be unique to the application; a proof made under one `ctx` fails under any other.
  Put a message, sender or epoch into it if a proof must not be reusable within the application.
- **A range proof is not a balance.** Read integer conservation from commitments only with a
  range proof on every term and verifier-fixed small coefficients (ADR-0051 D3a). Authorization and
  replay protection are the application's: see the reference state machine in
  `zeroj-integration-tests` (`org.zeroj.it.confidential`).
- **Verdicts:** `true`, `false` (including an identity commitment), or a
  `CommitmentFormatException` for a malformed input. The verdict is deterministic, identical on the
  pure-Java and blst providers, and its work is bounded by `n`.
- **Proving is offline/isolated only.** The prover is not constant-time on either provider; it draws
  fresh nonces from its own `SecureRandom`, and the runtime's entropy configuration is trusted.
- **No on-chain verifier:** Plutus V3 has no SHAKE128. The verifier algebra's cost on Cardano is in
  the [measurements](../docs/benchmarks/bulletproof-range-g1-2026-10-25.md).
- **Cost** (pure Java, M4 Max): proving takes about 1.6 / 3.1 / 6.2 s and verifying about
  0.47 / 0.77 / 1.33 s at `n` = 16 / 32 / 64.
- Registry status: `active` (experimental) in
  [`commitment-profiles-v1`](../docs/specs/commitment-profiles-v1.md) §2.3. Not approved for
  value-bearing or mainnet use without external review.

## Gradle

```gradle
dependencies {
    implementation 'org.zeroj:zeroj-bls12381'
}
```
