# zeroj-bls12381-wasm

Optional BLS12-381 provider backed by the Rust `bls12_381` crate compiled to
`wasm32-unknown-unknown` and loaded through Chicory.

## Reproducible build inputs

- Rust is pinned by `rust/rust-toolchain.toml`.
- The WASM target is declared in the pinned toolchain file.
- Rust dependencies are locked by `rust/Cargo.lock`.
- The generated `zeroj_bls12381.wasm` artifact is not checked in. Gradle builds
  it from source and packages it as `zeroj-bls12381/zeroj_bls12381.wasm`.

Build and test the module with:

```bash
./gradlew :zeroj-bls12381-wasm:test
```

Build only the Rust artifact with:

```bash
cd zeroj-bls12381-wasm/rust
cargo build --release --target wasm32-unknown-unknown
```
