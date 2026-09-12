# Contributing to ZeroJ

Thank you for your interest in contributing to ZeroJ!

## Development Setup

### Required

1. Install Java 25 (GraalVM recommended):
   ```bash
   sdk install java 25.0.2-graal
   sdk use java 25.0.2-graal
   ```

2. Build the project:
   ```bash
   ./gradlew build
   ```

3. Run tests:
   ```bash
   ./gradlew test
   ```

The default build is pure Java. It needs **no** Go, Rust, Cargo, Node.js, WASM toolchain, or RocksDB JNI.

### Optional opt-in builds

Everything below is outside the default build and never published ([ADR-0044](docs/adr/0044-focused-module-surface-and-optional-provider-isolation.md)).

**BLS/BBS WASM differential oracles** (requires Rust stable + the `wasm32-unknown-unknown` target):
```bash
rustup target add wasm32-unknown-unknown
./gradlew -PincludeAssurance \
  :zeroj-bls12381-wasm:test :zeroj-bbs-wasm:test :zeroj-bbs:test
```
`:zeroj-bbs:test` is part of that command on purpose — it is what runs the official CFRG vectors through the WASM provider row. CI runs the same command in `.github/workflows/assurance.yml`.

**gnark PlonK fixture oracle** (requires Go 1.24+):
```bash
cd assurance/gnark-fixtures && make gen-scratch
```

**MPF/JMT load and benchmark tools** (requires RocksDB JNI):
```bash
./gradlew -PincludeBenchmarks \
  :zeroj-mpf-poseidon-load:build :zeroj-jmt-poseidon-load:build
```

**Circuit development / interoperability tests** (requires Node.js 18+):
```bash
cargo install circom
npm install -g snarkjs
```
snarkjs is an independent prover oracle: `./gradlew :zeroj-integration-tests:e2eTest` has snarkjs prove circuits ZeroJ compiled, then verifies them with ZeroJ's pure-Java verifier.

## Project Structure

ZeroJ is a Gradle multi-module project. All module names use the `zeroj-` prefix and all packages start with `org.zeroj`.

Projects fall into four groups ([ADR-0044](docs/adr/0044-focused-module-surface-and-optional-provider-isolation.md)):

- **core product modules** at the repository root, constrained by `zeroj-bom-core`;
- **explicit opt-in product modules** — also at the root and published, but declared by coordinate and version rather than through the stable BOM: `zeroj-verifier-plonk`, `zeroj-bbs`, `zeroj-mpf-poseidon`, `zeroj-jmt-poseidon`;
- **support projects**, never published: `zeroj-test-vectors`, `zeroj-integration-tests`;
- **opt-in assurance and benchmark projects**, outside the default build and never published: `assurance/`, `benchmarks/`.

`./gradlew verifyDefaultModuleSurface` enforces those boundaries; it runs in CI, snapshot and release. If you add a dependency it rejects, that is the intended signal, not a bug in the check.

See [docs/architecture-overview.md](docs/architecture-overview.md) for the full module dependency graph and each module's README for details.

## Code Style

- Java 25 — use records, sealed interfaces, and pattern matching where appropriate
- All types in `zeroj-api` must be immutable
- Fail fast on malformed input — no silent defaults
- GraalVM native-image compatible — avoid unnecessary reflection
- Include `META-INF/native-image/` configs for any new module

## Testing

- Write tests for new functionality using JUnit 5
- Use test vectors from `zeroj-test-vectors` for proof-related tests
- Run the full suite before submitting: `./gradlew test`

## Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for new functionality
4. Ensure `./gradlew build` passes
5. Submit a pull request

## Architecture Decision Records

Significant design decisions are documented as ADRs in `docs/adr/`. Please read the relevant ADRs before making changes to the architecture.
