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

## Gradle

```gradle
dependencies {
    implementation 'org.zeroj:zeroj-bls12381'
}
```
