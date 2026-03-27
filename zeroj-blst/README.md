# zeroj-blst

BLS12-381 cryptographic operations via the [blst](https://github.com/supranational/blst) native library.

This module wraps the `blst-java` library to provide BLS12-381 pairing operations used by `zeroj-verifier-groth16` for high-performance Groth16 verification. BLS12-381 is the curve used by Cardano's Plutus V3 native BLS primitives.

## Key Types

| Type | Description |
|------|-------------|
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
