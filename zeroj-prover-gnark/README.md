# zeroj-prover-gnark

Native in-process Groth16 and PlonK proving via [gnark](https://github.com/Consensys/gnark) FFM bindings.

This module provides high-performance in-process proof generation using gnark (Go-based ZK framework), accessed through Java's Foreign Function & Memory (FFM) API. ZeroJ's Cardano path uses **BLS12-381**. BN254 should be treated as legacy/off-chain only and is not suitable for Cardano on-chain verification.

## Features

- Groth16 proving for BLS12-381
- PlonK proving (beta) for BLS12-381
- Legacy/off-chain BN254 proving through `GnarkProver` requires `-Dzeroj.allowLegacyBn254=true`; ZeroJ BN254 verifiers are also disabled by default
- Uses shared `zeroj-prover-spi` response and error types
- `AutoCloseable` for proper native resource management

## Key Types

| Type | Description |
|------|-------------|
| `GnarkProver` | Native prover — `proveRaw(curve, r1csPath, pkPath, witnessPath)` |
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

The checked-in native resource is built for the current development host. Before
publishing or testing on another platform, run `make build` on that target so
`src/main/resources/native/<platform>-<arch>/` contains the matching shared
library.

## Usage

```java
try (var prover = new GnarkProver()) {
    // Groth16 proving
    ProveResponse response = prover.proveRaw(
            "bls12381",
            Path.of("circuit.r1cs"),
            Path.of("proving_key.bin"),
            Path.of("witness.bin"));

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
