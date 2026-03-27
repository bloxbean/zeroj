# zeroj-prover-gnark

Native in-process Groth16 and PlonK proving via [gnark](https://github.com/Consensys/gnark) FFM bindings.

This module provides high-performance in-process proof generation using gnark (Go-based ZK framework), accessed through Java's Foreign Function & Memory (FFM) API. It supports **both BLS12-381 and BN254** curves, making it the only prover backend that covers all curves.

## Features

- Groth16 proving for BLS12-381 and BN254
- PlonK proving (beta) for BLS12-381 and BN254
- Implements `ProverService` interface (drop-in replacement for sidecar client)
- `AutoCloseable` for proper native resource management

## Key Types

| Type | Description |
|------|-------------|
| `GnarkProver` | Native prover — `proveRaw(curveId, r1cs, pkPath, witnessPath)` |
| `PlonkGnarkVerifier` | PlonK proof verification via gnark (separate from Groth16 verifiers) |
| `GnarkLibrary` | FFM bindings to `libzeroj_gnark` |
| `GnarkNativeLoader` | Library loading and initialization |

## Prerequisites

### Building the Native Library

The gnark wrapper must be compiled from Go source:

```bash
# Requires: Go 1.21+, CGO enabled
cd zeroj-prover-gnark/gnark-wrapper
make build
```

This produces `libzeroj_gnark.dylib` (macOS) or `libzeroj_gnark.so` (Linux) in `src/main/resources/native/<platform>-<arch>/`.

### Runtime

The compiled native library must be on the classpath or system library path. The library is large (~30-50MB) because it includes the Go runtime.

## Usage

```java
try (var prover = new GnarkProver()) {
    // Groth16 proving
    ProveResponse response = prover.proveRaw(
            CurveId.BLS12_381, r1csBytes, pkPath, witnessPath);

    // Check version
    String version = prover.gnarkVersion();
}
```

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-prover-gnark'
}
```
