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

### Optional (for native modules)

**gnark prover** (requires Go 1.21+):
```bash
cd zeroj-prover-gnark/gnark-wrapper
make build
```

**Halo2 verifier** (requires Rust stable):
```bash
cd zeroj-verifier-halo2/halo2-rust
cargo build --release
```

**Circuit development** (requires Node.js 18+):
```bash
cargo install circom
npm install -g snarkjs
```

## Project Structure

ZeroJ is a Gradle multi-module project. All module names use the `zeroj-` prefix and all packages start with `com.bloxbean.cardano.zeroj`.

See [docs/architecture-overview.md](docs/architecture-overview.md) for the full module dependency graph and each module's [README](zeroj-api/README.md) for details.

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
