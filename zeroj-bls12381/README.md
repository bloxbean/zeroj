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

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-bls12381'
}
```
