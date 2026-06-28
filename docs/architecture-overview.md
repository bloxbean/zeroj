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
defined in Java or imported from external toolchains. Proofs can be generated
with the pure Java prover or the gnark native accelerator. Verification is Java
first, and on-chain verification uses Julc-compiled Plutus V3 validators. gnark
binary PlonK artifacts remain on the gnark native verification path until a
structured proof adapter is added.

## Module Organization

Modules are organized into core modules, mainline opt-in modules, and incubator
modules. `zeroj-bom-core` covers the v3 core privacy path. `zeroj-bom-all`
covers core plus opt-in BBS/WASM and incubator modules.

## Module Dependency Graph

```
zeroj-api                  (foundation types)
  |
  +-- zeroj-codec          (→ zeroj-api, jackson, cbor)
  |
  +-- zeroj-backend-spi    (→ zeroj-api)
  |     |
  |     +-- zeroj-verifier-core    (→ zeroj-api, zeroj-backend-spi)
  |     |
  |     +-- zeroj-verifier-groth16 (→ zeroj-backend-spi, zeroj-codec, zeroj-bls12381, zeroj-blst)
  |     |
  |     +-- zeroj-verifier-plonk   (→ zeroj-backend-spi, zeroj-codec, zeroj-crypto, zeroj-verifier-groth16 for BN254 arithmetic)
  +-- zeroj-bls12381       (pure Java BLS12-381 field/curve/pairing)
  |     |
  |     +-- zeroj-crypto   (→ zeroj-api, zeroj-bls12381)
  |
  +-- zeroj-blst           (→ zeroj-api, blst-java)
  |
  +-- zeroj-circuit-dsl    (→ zeroj-api, zeroj-codec)
  |     |
  |     +-- zeroj-circuit-lib (→ zeroj-circuit-dsl)
  |
  +-- zeroj-patterns       (→ zeroj-api, zeroj-verifier-core, zeroj-codec, zeroj-cardano)
  |
  +-- zeroj-cardano        (→ zeroj-api, cbor)
  |     |
  |     +-- zeroj-ccl      (→ zeroj-cardano, zeroj-api, cardano-client-lib)
  |
  +-- zeroj-prover-spi     (prover request/response contracts)
  |     |
  |     +-- zeroj-prover-gnark (→ zeroj-api, zeroj-codec, zeroj-circuit-dsl, Go FFM)
  |
  +-- zeroj-prover-wasm      (→ zeroj-api, GraalVM WASM) [incubator]
  |
  +-- zeroj-onchain-julc   (→ zeroj-crypto, julc-stdlib, BLS12-381 builtins)
  |
  +-- zeroj-test-vectors   (→ zeroj-api, test fixtures only)

zeroj-bbs, zeroj-bbs-wasm, zeroj-bls12381-wasm (mainline opt-in)

zeroj-bom-core / zeroj-bom-all (platform modules, no code)
```

## Layer Separation

### Layer 1: Core Model (`zeroj-api`)
Immutable data types shared across all modules:
- `ZkProofEnvelope` -- the proof container
- `ProofSystemId` -- public docs focus on GROTH16, PLONK, and BBS
- `CurveId` -- public docs focus on BN254 and BLS12_381
- `VerificationResult` -- crypto validity + policy validity
- `VerificationMaterial` -- verification key + metadata

### Layer 2: Serialization (`zeroj-codec`)
Proof format parsers and serializers:
- snarkjs JSON format (proof.json, verification_key.json, public.json)
- gnark PlonK/Groth16 format
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
- `zeroj-verifier-groth16` -- Groth16 for BN254 (pure Java) + BLS12-381 (pure Java / blst)
- `zeroj-verifier-plonk` -- structured PlonK proof verification for BN254 + BLS12-381 (pure Java)
- `zeroj-blst` -- Low-level BLS12-381 curve operations

### Layer 5: Circuit Definition (`zeroj-circuit-dsl`, `zeroj-circuit-lib`)
Java circuit definition and compilation:
- `CircuitBuilder` / `CircuitAPI` -- define circuits in Java
- `SignalBuilder` -- OO Signal-style API
- Compiles to R1CS (Groth16) or PlonK gates
- `zeroj-circuit-lib` -- Poseidon, MiMC, Merkle, comparators, binary ops

### Layer 6: Orchestration (`zeroj-verifier-core`)
Routes verification requests to the correct backend based on proof system and curve.

### Layer 7: Proving
Proof generation backends:
- `zeroj-crypto` -- pure Java Groth16 and PlonK proving where supported
- `zeroj-prover-spi` -- minimal prover-side request/response contract
- `zeroj-prover-gnark` -- optional native Groth16/PlonK proving via Go FFM
- `zeroj-prover-wasm` -- Circom witness calculation via GraalVM WASM (incubator)

### Layer 8: High-Level Patterns (`zeroj-patterns`)
Domain-specific APIs:
- State transitions, nullifier claims, membership proofs
- Typed inputs, enriched results, pre-built policies

### Layer 9: Cardano Integration
Anchoring verified results on L1:
- `zeroj-cardano` -- Anchor model, CIP-10 metadata encoding
- `zeroj-ccl` -- Cardano Client Lib transaction builder integration

### Layer 10: On-Chain Verification (`zeroj-onchain-julc`)
Reusable Plutus V3 spending validators compiled via Julc:
- `groth16.validator.Groth16BLS12381Verifier` -- on-chain Groth16 verification using BLS12-381 builtins and arbitrary public-input counts
- `groth16.lib.Groth16BLS12381Lib` -- reusable `@OnchainLibrary` Groth16 verification helper for custom validators
- `groth16.codec.SnarkjsToCardano` and `groth16.codec.ProverToCardano` -- convert proof/VK artifacts to BLS compressed bytes for on-chain use
- `plonk.codec.PlonKProverToCardano` -- converts ZeroJ pure-Java BLS12-381 PlonK proofs and verification keys to the Cardano compressed profile
- `plonk.validator.PlonkBLS12381Verifier` -- experimental opt-in on-chain PlonK verifier for the current one-public-input BLS12-381 Cardano profile with compressed transcript binding and full KZG batch opening check
- `plonk.validator.PlonkBLS12381TranscriptPrototype` -- gnark transcript regression prototype, not a trustless verifier
- `analysis.ScriptBudgetEstimator`, `analysis.OnChainFeasibility`, `deployment.ReferenceScriptDeployer` -- on-chain budget and deployment helpers

## Crypto Backend Strategy

| Proof System | Curve | Backend | Implementation | Native Deps |
|-------------|-------|---------|----------------|-------------|
| Groth16 | BLS12-381 | Pure Java | `zeroj-verifier-groth16` | None |
| Groth16 | BLS12-381 | blst native (FFM) | `zeroj-verifier-groth16` | blst |
| Groth16 | BN254 | Pure Java | `zeroj-verifier-groth16` | None |
| PlonK | BLS12-381 | Pure Java | `zeroj-verifier-plonk` | None |
| PlonK | BN254 | Pure Java | `zeroj-verifier-plonk` | None |

- BLS12-381 pure Java verifier uses field arithmetic validated against gnark
- BN254 uses pure Java field arithmetic, validated against Ethereum EIP-196/197 test vectors
- blst option available for BLS12-381 when a native verifier backend is acceptable

## On-Chain Verification

On-chain ZK verification uses Julc (Java-to-Plutus compiler) to create reusable Plutus V3 spending validators:

| Proof System | Curve | On-Chain Status | Module |
|-------------|-------|----------------|--------|
| Groth16 | BLS12-381 | Working | `zeroj-onchain-julc` |
| PlonK | BLS12-381 | Experimental opt-in full verifier for current one-public-input Cardano profile; audit pending | `zeroj-onchain-julc` |
| Groth16/PlonK | BN254 | Not feasible | No Plutus BN254 builtins |

The `zeroj-examples` module includes complete end-to-end tests (DSL to on-chain execution on Yaci DevKit).

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
| [0003](adr/0003-pure-java-mvp.md) | Hybrid: blst for BLS12-381, pure Java for BN254 |
| [0006](adr/0006-separation-of-crypto-and-policy-verification.md) | Separate crypto and policy verification |
| [0007](adr/0007-module-structure-and-boundaries.md) | Multi-module structure |
| [0008](adr/0008-plonk-support-via-gnark.md) | PlonK support via gnark |
| [0010](adr/0010-java-circuit-dsl.md) | Java Circuit DSL |
| [0012](adr/0012-pure-java-provers-groth16-plonk.md) | Pure Java Groth16 and PlonK provers |
| [0020](adr/0020-module-cleanup-and-core-restructure.md) | Module cleanup and core restructure |
