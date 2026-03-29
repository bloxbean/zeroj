# zeroj-prover-rapidsnark

Native in-process Groth16/BN254 proving via [rapidsnark](https://github.com/iden3/rapidsnark) FFM bindings.

This module provides high-performance in-process proof generation for Groth16/BN254 circuits using the rapidsnark native library, accessed through Java's Foreign Function & Memory (FFM) API. It avoids the overhead of an external sidecar process.

## Features

- In-process proof generation (no HTTP overhead)
- BN254 curve support (Groth16)
- Implements `ProverService` interface (drop-in replacement for sidecar client)
- `AutoCloseable` for proper native resource management

## Native Libraries

The `librapidsnark` native binaries are **not** checked into git. They are downloaded automatically from [iden3/rapidsnark GitHub releases](https://github.com/iden3/rapidsnark/releases) when you build the module.

### Automatic download (recommended)

```bash
# Downloads all platform binaries, then builds
./gradlew :zeroj-prover-rapidsnark:build

# Or download only
./gradlew :zeroj-prover-rapidsnark:downloadNativeLib
```

The `downloadNativeLib` task downloads pre-built binaries for all supported platforms and places them under `src/main/resources/native/`. If a binary already exists locally, it is skipped.

### Supported platforms

| Platform | Library |
|----------|---------|
| linux-x86_64 | `librapidsnark.so` |
| linux-arm64 | `librapidsnark.so` |
| macos-x86_64 | `librapidsnark.dylib` |
| macos-arm64 | `librapidsnark.dylib` |

### Build from source

To build rapidsnark from source instead of downloading pre-built binaries:

```bash
git clone https://github.com/iden3/rapidsnark.git
cd rapidsnark
git submodule init && git submodule update
./build_gmp.sh host
mkdir build_prover && cd build_prover
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=../package
make -j$(nproc) && make install
```

Then copy the resulting `librapidsnark.so` or `librapidsnark.dylib` to the appropriate `src/main/resources/native/<platform>-<arch>/` directory.

## License

This module (zeroj-prover-rapidsnark) is MIT-licensed as part of ZeroJ.

The `librapidsnark` native libraries are from
[iden3/rapidsnark](https://github.com/iden3/rapidsnark) and are licensed
under **LGPL-3.0**. Because rapidsnark is loaded as a shared library
(dynamic linking via FFM), your application code is NOT subject to the
LGPL. You may replace the library with your own modified build.

See [NOTICE](NOTICE) for full details and [LICENSES/](LICENSES/) for
the LGPL-3.0 and GPL-3.0 license texts.

## Key Types

| Type | Description |
|------|-------------|
| `RapidsnarkProver` | Native prover — `proveRaw(zkey, witness)` or file-based API |
| `RapidsnarkLibrary` | FFM bindings to `librapidsnark` |
| `NativeLibraryLoader` | Classpath extraction / system library search |

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
- This module is in **incubator** status and is not published to Maven Central
