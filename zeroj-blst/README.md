# zeroj-blst

BLS12-381 cryptographic operations via the [blst](https://github.com/supranational/blst) native library.

This module wraps the `blst-java` library to provide BLS12-381 pairing operations used by `zeroj-verifier-groth16` for high-performance Groth16 verification. It also exposes an explicit `Bls12381Provider` implementation for protocols such as BBS that can opt in to native-backed BLS12-381 operations. BLS12-381 is the curve used by Cardano's Plutus V3 native BLS primitives.

## Key Types

| Type | Description |
|------|-------------|
| `BlstBls12381Provider` | Explicit native-backed `Bls12381Provider` implementation |
| `BlstPairing` | Wrapper for blst FFM pairing operations (multi-pairing, point validation) |

## Why blst?

| Property | Value |
|----------|-------|
| Performance | ~1ms verification (vs ~100-300ms pure Java BN254) |
| Library | `foundation.icon:blst-java:0.3.2` (same as julc-bls) |
| Platforms | Linux (x86_64, aarch64), macOS (x86_64, arm64) |
| GraalVM | Compatible via FFM |

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-blst'
}
```

Most users don't depend on this module directly — it is pulled in transitively by `zeroj-verifier-groth16`.

Provider selection remains explicit:

```java
var bls = com.bloxbean.cardano.zeroj.blst.BlstBls12381Provider.createDefault();
var bbs = com.bloxbean.cardano.zeroj.bbs.BbsService.withBlsProvider(
        com.bloxbean.cardano.zeroj.bbs.BbsCiphersuite.BLS12381_SHA256,
        bls);
```
