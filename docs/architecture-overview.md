# ZeroJ Architecture Overview

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Module Organization](#module-organization)
- [Module Dependency Graph](#module-dependency-graph)
- [Layer Separation](#layer-separation)
- [Crypto Backend Strategy](#crypto-backend-strategy)
- [On-Chain Verification](#on-chain-verification)
- [GraalVM Native Image](#graalvm-native-image)
- [Key ADRs](#key-adrs)

---

## Design Philosophy

ZeroJ is a privacy-first ZK platform for Java and Cardano. Circuits can be
defined in Java or imported from external toolchains. Proofs are generated with
the pure Java prover, optionally accelerated by blst. Verification is Java first,
and on-chain verification uses Julc-compiled Plutus V3 validators. The default
build is pure Java and needs no Go, Rust, Cargo, Node.js, WASM toolchain, or
RocksDB JNI.

## Module Organization

Per [ADR-0044](adr/0044-focused-module-surface-and-optional-provider-isolation.md),
projects fall into four groups:

- **Core product modules**, constrained by `zeroj-bom-core` — the single stable BOM.
- **Explicit opt-in product modules** — published, but declared by coordinate and
  version rather than through the stable BOM: `zeroj-verifier-plonk`, `zeroj-bbs`,
  `zeroj-mpf-poseidon`, `zeroj-jmt-poseidon`.
- **Support projects**, never published: `zeroj-test-vectors`, `zeroj-integration-tests`.
- **Opt-in assurance and benchmark projects**, outside the default build and never
  published: `assurance/` (independent WASM differential providers, the pinned gnark
  fixture generator) and `benchmarks/` (MPF/JMT load tools).

## Module Dependency Graph

```
zeroj-api                  (foundation types)
  |
  +-- zeroj-codec          (→ zeroj-api, jackson, cbor)
  |
  +-- zeroj-backend-spi    (→ zeroj-api; SPI + verifier registry/orchestrator)
  |     |
  |     +-- zeroj-verifier-groth16 (→ zeroj-backend-spi, zeroj-codec, zeroj-bls12381, zeroj-blst)
  |     |
  |     +-- zeroj-verifier-plonk   (→ zeroj-backend-spi, zeroj-codec, zeroj-crypto, zeroj-verifier-groth16 for legacy BN254 arithmetic)
  +-- zeroj-bls12381       (pure Java BLS12-381 field/curve/pairing)
  |     |
  |     +-- zeroj-crypto   (→ zeroj-api, zeroj-bls12381)
  |
  +-- zeroj-blst           (→ zeroj-api, libblst via FFM)
  |
  +-- zeroj-circuit-dsl    (→ zeroj-api, zeroj-codec)
  |     |
  |     +-- zeroj-circuit-lib (→ zeroj-circuit-dsl)
  |             |
  |             +-- zeroj-mpf-poseidon (→ CCL MPF/core; structure-owned circuits)
  |             |
  |             +-- zeroj-jmt-poseidon (→ CCL JMT/core; structure-owned circuits)
  |
  +-- zeroj-tools          (→ zeroj-bls12381, zeroj-crypto; ceremony library + zeroj-ceremony CLI)
  |
  +-- zeroj-onchain-julc   (→ zeroj-crypto, julc-stdlib, BLS12-381 builtins)
  |
  +-- zeroj-test-vectors   (→ zeroj-api, test fixtures only)

zeroj-bbs                (→ zeroj-api, zeroj-backend-spi, zeroj-bls12381)  [opt-in product]

zeroj-integration-tests  (cross-module regressions; never published)

zeroj-bom-core           (the single stable BOM; no code)

--- outside the default build, never published -------------------------------
assurance/zeroj-bls12381-wasm, assurance/zeroj-bbs-wasm   -PincludeAssurance
assurance/gnark-fixtures  (pinned gnark PlonK fixture generator; not a Gradle project)
benchmarks/zeroj-mpf-poseidon-load, benchmarks/zeroj-jmt-poseidon-load  -PincludeBenchmarks
```

## Layer Separation

### Layer 1: Core Model (`zeroj-api`)
Immutable data types shared across all modules:
- `ZkProofEnvelope` -- the proof container
- `ProofSystemId` -- public docs focus on GROTH16, PLONK, and BBS
- `CurveId` -- public docs focus on BLS12_381 for Cardano-facing flows
- `VerificationResult` -- crypto validity + policy validity
- `VerificationMaterial` -- verification key + metadata

### Layer 2: Serialization (`zeroj-codec`)
Proof format parsers and serializers:
- snarkjs JSON format (proof.json, verification_key.json, public.json)
- gnark-compatible PlonK/Groth16 format
- CBOR binary format for network transmission
- Canonical hashing for deterministic proof identification

### Layer 3: Verification SPI (`zeroj-backend-spi`)
Backend abstraction:
- `ZkVerifier` interface -- the core verification contract
- `VerificationKeyRegistry` -- VK storage and lookup
- `BackendDescriptor` -- declares what a backend supports
- ServiceLoader-based discovery

### Layer 4: Verification Backends
Concrete implementations:
- `zeroj-verifier-groth16` -- Groth16 for BLS12-381 (pure Java / blst); BN254 legacy verifier disabled by default
- `zeroj-verifier-plonk` -- structured PlonK proof verification for BLS12-381 (pure Java); BN254 legacy verifier disabled by default
- `zeroj-blst` -- Low-level BLS12-381 curve operations

### Layer 5: Circuit Definition (`zeroj-circuit-dsl`, `zeroj-circuit-lib`)
Java circuit definition and compilation:
- `CircuitBuilder` / `CircuitAPI` -- define circuits in Java
- `SignalBuilder` -- OO Signal-style API
- Compiles to R1CS (Groth16) or PlonK gates
- `zeroj-circuit-lib` -- Poseidon, MiMC, Merkle, comparators, binary ops

### Layer 6: Orchestration (`zeroj-backend-spi`)
`VerifierRegistry` and `VerifierOrchestrator` route verification requests to the
correct backend based on proof system and curve. They live in
`zeroj-backend-spi` and keep their `com.bloxbean.cardano.zeroj.verifier.core`
package; ADR-0044 merged the former `zeroj-verifier-core` artifact into the SPI
artifact without changing selection, key lookup, result, or failure semantics.

### Layer 7: Proving
- `zeroj-crypto` -- pure Java Groth16 and PlonK proving; the product proving path
- `zeroj-crypto-blst` -- opt-in bridge wiring blst's native MSM into the
  `zeroj-crypto` prover backend, producing bit-identical proofs

ZeroJ ships no provider-neutral proving SPI. ADR-0044 removed the unimplemented
`zeroj-prover-spi` abstraction rather than move it into a retained module; a
future unified contract would have to model setup/key reuse, artifact ownership,
secret lifetime, progress and cancellation, and needs its own accepted design.

### Layer 8: Application Policy — deliberately out of scope
ZeroJ ships no generic membership, nullifier, or state-transition helpers.
Cryptographic proof validity is not application authorization: `ScriptContext`
binding, replay protection, nullifier registries, and business policy are the
application's responsibility. See
[zeroj-usecases](https://github.com/bloxbean/zeroj-usecases) for worked examples.

### Layer 9: Operator Tooling (`zeroj-tools`)
- `ZkeyContributor`, `SnarkjsHashToG2`, `ChaChaRng` -- the snarkjs-compatible
  Groth16 phase-2 contribution engine, embeddable as a library
- `CeremonyCli` -- the `zeroj-ceremony` command (export-r1cs, contribute, finalize)

### Layer 10: On-Chain Verification (`zeroj-onchain-julc`)
Reusable Plutus V3 spending validators compiled via Julc:
- `groth16.validator.Groth16BLS12381Verifier` -- on-chain Groth16 verification using BLS12-381 builtins and arbitrary public-input counts
- `groth16.lib.Groth16BLS12381Lib` -- reusable `@OnchainLibrary` Groth16 verification helper for custom validators
- `groth16.codec.SnarkjsToCardano` and `groth16.codec.ProverToCardano` -- convert proof/VK artifacts to BLS compressed bytes for on-chain use
- `plonk.codec.PlonKProverToCardano` -- converts ZeroJ pure-Java BLS12-381 PlonK proofs and verification keys to the Cardano compressed profile
- `plonk.lib.PlonkBLS12381Lib` -- reusable `@OnchainLibrary` PlonK verification helper for custom validators
- `plonk.validator.PlonkBLS12381Verifier` -- experimental opt-in on-chain PlonK verifier for the current one-public-input BLS12-381 Cardano profile with compressed transcript binding and full KZG batch opening check
- `plonk.validator.PlonkBLS12381MultiInputVerifier` and `PlonkBLS12381MultiInputParamVerifier` -- experimental opt-in bounded MPI PlonK validators for datum-supplied or script-parameter public inputs
- `analysis.ScriptBudgetEstimator`, `analysis.OnChainFeasibility`, `deployment.ReferenceScriptDeployer` -- on-chain budget and deployment helpers

## Crypto Backend Strategy

| Proof System | Curve | Backend | Implementation | Native Deps |
|-------------|-------|---------|----------------|-------------|
| Groth16 | BLS12-381 | Pure Java (default) | `zeroj-verifier-groth16`, `zeroj-crypto` | None |
| Groth16 | BLS12-381 | blst native (opt-in) | `zeroj-crypto-blst` (bridges `zeroj-blst`) | `libblst` via FFM |
| PlonK | BLS12-381 | Pure Java | `zeroj-verifier-plonk` | None |

- **Pure Java is the default** for both proving and verification; it matches blst's speed at large circuit sizes (ADR-0033/0034), so blst is opt-in acceleration, not a requirement.
- `zeroj-blst` binds `libblst` (built from source) via the Java **FFM** API — not JNI/SWIG.
- BLS12-381 pure Java verifier uses field arithmetic validated against independent implementations (gnark-generated PlonK vectors, snarkjs artifacts, zkcrypto WASM and blst providers).
- BN254 pure Java arithmetic remains for legacy/off-chain tests, but BN254 verifiers are disabled by default and are not ServiceLoader-registered.
- **In-circuit crypto gadgets** (Blake2b, SHA-512, HMAC-SHA512, Ed25519, BIP32, CIP-1852 — ADR-0027) let circuits reproduce Cardano key derivation; large circuits (millions of constraints) prove within commodity memory via a streaming setup + `mmap`'d key (ADR-0033/0034/0035), driven by the `Groth16Keys`/`Groth16Pipeline` facade (ADR-0036).

## On-Chain Verification

On-chain ZK verification uses Julc (Java-to-Plutus compiler) to create reusable Plutus V3 spending validators:

| Proof System | Curve | On-Chain Status | Module |
|-------------|-------|----------------|--------|
| Groth16 | BLS12-381 | Working | `zeroj-onchain-julc` |
| PlonK | BLS12-381 | Experimental opt-in full verifiers for current Cardano profiles; audit pending | `zeroj-onchain-julc` |
| Groth16/PlonK | BN254 | Not feasible | No Plutus BN254 builtins |

The `zeroj-integration-tests` project holds the cross-module end-to-end regressions (DSL to on-chain execution on Yaci DevKit, snarkjs interoperability, proof tampering and invalid-witness rejection).

## GraalVM Native Image

Runtime modules that need native-image metadata keep configuration files in:
```
src/main/resources/META-INF/native-image/com.bloxbean.cardano/<module>/
```

Best-effort compatibility from the start; hardened in later milestones.

## Key ADRs

| ADR | Decision |
|-----|----------|
| [0001](adr/0001-verifier-first-architecture.md) | Verifier-first, no prover in core |
| [0003](adr/0003-pure-java-mvp.md) | Pure-Java MVP; blst native is opt-in acceleration |
| [0006](adr/0006-separation-of-crypto-and-policy-verification.md) | Separate crypto and policy verification |
| [0007](adr/0007-module-structure-and-boundaries.md) | Multi-module structure |
| [0008](adr/0008-plonk-support-via-gnark.md) | PlonK support via gnark |
| [0010](adr/0010-java-circuit-dsl.md) | Java Circuit DSL |
| [0012](adr/0012-pure-java-provers-groth16-plonk.md) | Pure Java Groth16 and PlonK provers |
| [0020](adr/0020-module-cleanup-and-core-restructure.md) | Module cleanup and core restructure |
| [0027](adr/0027-real-world-crypto-gadgets-sha512-hmac-blake2b-ed25519.md) | Real-world crypto gadgets (SHA-512/HMAC/Blake2b/Ed25519/BIP32/CIP-1852) |
| [0029](adr/0029-blst-accelerated-groth16-prover.md) | Groth16 prover performance (blst/FFM + memory) |
| [0033](adr/0033-prover-memory-reduction.md)–[0035](adr/0035-setup-memory-time-reduction.md) | Prover & setup memory/time reduction |
| [0036](adr/0036-groth16-api-facade-and-pipeline.md) | Groth16 API facade & pipeline |

The full ADR history lives in [`adr/`](adr/).
