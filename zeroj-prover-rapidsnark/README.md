# zeroj-prover-rapidsnark

Native in-process Groth16/BN254 proving via [rapidsnark](https://github.com/nicola-masarone/rapidsnark) FFM bindings.

This module provides high-performance in-process proof generation for Groth16/BN254 circuits using the rapidsnark native library, accessed through Java's Foreign Function & Memory (FFM) API. It avoids the overhead of an external sidecar process.

## Features

- In-process proof generation (no HTTP overhead)
- BN254 curve support (Groth16)
- Implements `ProverService` interface (drop-in replacement for sidecar client)
- `AutoCloseable` for proper native resource management

## Key Types

| Type | Description |
|------|-------------|
| `RapidsnarkProver` | Native prover — `proveRaw(zkey, witness)` or file-based API |
| `RapidsnarkLibrary` | FFM bindings to `librapidsnark` |
| `NativeLibraryLoader` | Classpath extraction / system library search |

## Prerequisites

The `librapidsnark` native library must be available:
- Linux: `librapidsnark.so`
- macOS: `librapidsnark.dylib`

Place on the system library path or bundle in classpath under `native/<platform>-<arch>/`.

## Usage

```java
try (var prover = new RapidsnarkProver()) {
    // From byte arrays
    ProveResponse response = prover.proveRaw(zkeyBytes, witnessBytes);

    // From files
    ProveResponse response = prover.proveRaw(Path.of("circuit.zkey"), Path.of("witness.wtns"));
}
```

## Limitations

- **BN254 only** — for BLS12-381 proving, use `zeroj-prover-gnark`
- Requires pre-compiled native library for your platform

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-prover-rapidsnark'
}
```
