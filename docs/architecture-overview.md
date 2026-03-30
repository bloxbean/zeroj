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

ZeroJ is a **verifier-first** ZK platform. Circuits can be defined in Java (DSL) or externally (circom, gnark Go). Proofs are generated in-process (gnark FFM) or externally (snarkjs). Verification is pure Java. On-chain verification uses Julc-compiled Plutus V3 validators.

## Module Organization

Modules are organized into **core** (top-level) and **incubator** (`incubator/` subfolder). Incubator modules are experimental or alternative backends -- still compiled, tested, and published, but visually separated.

## Module Dependency Graph

```
zeroj-api                  (no project deps — foundation types)
  |
  +-- zeroj-codec          (→ zeroj-api, jackson, cbor)
  |
  +-- zeroj-backend-spi    (→ zeroj-api)
  |     |
  |     +-- zeroj-verifier-core    (→ zeroj-api, zeroj-backend-spi)
  |     |
  |     +-- zeroj-verifier-groth16 (→ zeroj-backend-spi, zeroj-codec, zeroj-blst)
  |     |
  |     +-- zeroj-verifier-plonk   (→ zeroj-backend-spi, zeroj-codec, zeroj-blst)
  |     |
  |     +-- zeroj-verifier-halo2   (→ zeroj-backend-spi, zeroj-codec, Rust FFM) [incubator]
  |
  +-- zeroj-blst           (→ zeroj-api, blst-java)
  |
  +-- zeroj-circuit-dsl    (→ zeroj-api, zeroj-codec)
  |     |
  |     +-- zeroj-circuit-lib (→ zeroj-circuit-dsl)
  |
  +-- zeroj-submission     (→ zeroj-api, cbor)
  |     |
  |     +-- zeroj-ingestion (→ zeroj-submission, zeroj-verifier-core, zeroj-codec)
  |
  +-- zeroj-patterns       (→ zeroj-api, zeroj-verifier-core, zeroj-codec, zeroj-cardano)
  |
  +-- zeroj-cardano        (→ zeroj-api, cbor)
  |     |
  |     +-- zeroj-ccl      (→ zeroj-cardano, zeroj-api, cardano-client-lib)
  |
  +-- zeroj-prover-gnark   (→ zeroj-api, zeroj-codec, zeroj-backend-spi, Go FFM)
  |
  +-- zeroj-prover-sidecar (→ zeroj-api, zeroj-codec, jackson) [incubator]
  |     |
  |     +-- zeroj-prover-rapidsnark (→ zeroj-prover-sidecar, FFM) [incubator]
  |
  +-- zeroj-onchain-julc   (→ julc-stdlib, BLS12-381 builtins)
  |
  +-- zeroj-test-vectors   (→ zeroj-api, test fixtures only)

zeroj-bom                  (platform module, no code)
```

## Layer Separation

### Layer 1: Core Model (`zeroj-api`)
Immutable data types shared across all modules:
- `ZkProofEnvelope` -- the proof container
- `ProofSystemId` -- GROTH16, PLONK, FFLONK, HALO2
- `CurveId` -- BN254, BLS12_381, PALLAS
- `VerificationResult` -- crypto validity + policy validity
- `VerificationMaterial` -- verification key + metadata

### Layer 2: Serialization (`zeroj-codec`)
Proof format parsers and serializers:
- snarkjs JSON format (proof.json, verification_key.json, public.json)
- gnark PlonK/Groth16 format
- Halo2 proof format
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
- `zeroj-verifier-plonk` -- PlonK for BN254 + BLS12-381 (pure Java), byte-for-byte verified against gnark
- `zeroj-verifier-halo2` -- Halo2 IPA via Rust FFM (incubator)
- `zeroj-blst` -- Low-level BLS12-381 curve operations

### Layer 5: Circuit Definition (`zeroj-circuit-dsl`, `zeroj-circuit-lib`)
Java circuit definition and compilation:
- `CircuitBuilder` / `CircuitAPI` -- define circuits in Java
- `SignalBuilder` -- OO Signal-style API
- Compiles to R1CS (Groth16), PlonK gates, or Halo2 PLONKish
- `zeroj-circuit-lib` -- Poseidon, MiMC, Merkle, comparators, binary ops

### Layer 6: Orchestration (`zeroj-verifier-core`)
Routes verification requests to the correct backend based on proof system and curve.

### Layer 7: Proving
Proof generation backends:
- `zeroj-prover-gnark` -- in-process Groth16/PlonK via Go FFM (primary)
- `zeroj-prover-rapidsnark` -- in-process Groth16 BN254 via C++ FFM (incubator)
- `zeroj-prover-sidecar` -- HTTP client for external prover services (incubator)

### Layer 8: Submission & Ingestion
Proof-backed state transitions:
- `zeroj-submission` -- Wire format, Ed25519 signatures, result types
- `zeroj-ingestion` -- 6-stage validation pipeline, governance stores, audit

### Layer 9: High-Level Patterns (`zeroj-patterns`)
Domain-specific APIs:
- State transitions, nullifier claims, membership proofs
- Typed inputs, enriched results, pre-built policies

### Layer 10: Cardano Integration
Anchoring verified results on L1:
- `zeroj-cardano` -- Anchor model, CIP-10 metadata encoding
- `zeroj-ccl` -- Cardano Client Lib transaction builder integration

### Layer 11: On-Chain Verification (`zeroj-onchain-julc`)
Reusable Plutus V3 spending validators compiled via Julc:
- `Groth16BLS12381Verifier` -- on-chain Groth16 verification using BLS12-381 builtins
- `PlonkBLS12381FullVerifier` -- on-chain PlonK verification with Fiat-Shamir transcript
- `SnarkjsToCardano` -- converts snarkjs JSON to BLS compressed bytes for on-chain use

## Crypto Backend Strategy

| Proof System | Curve | Backend | Implementation | Native Deps |
|-------------|-------|---------|----------------|-------------|
| Groth16 | BLS12-381 | Pure Java | `zeroj-verifier-groth16` | None |
| Groth16 | BLS12-381 | blst native (FFM) | `zeroj-verifier-groth16` | blst (~1ms) |
| Groth16 | BN254 | Pure Java | `zeroj-verifier-groth16` | None |
| PlonK | BLS12-381 | Pure Java | `zeroj-verifier-plonk` | None |
| PlonK | BN254 | Pure Java | `zeroj-verifier-plonk` | None |
| Halo2 IPA | Pallas | Rust FFM | `zeroj-verifier-halo2` (incubator) | Rust binary |

- BLS12-381 pure Java verifier uses field arithmetic validated against gnark
- BN254 uses pure Java field arithmetic, validated against Ethereum EIP-196/197 test vectors
- blst option available for BLS12-381 when maximum performance is needed (~1ms vs ~100ms)

## On-Chain Verification

On-chain ZK verification uses Julc (Java-to-Plutus compiler) to create reusable Plutus V3 spending validators:

| Proof System | Curve | On-Chain Status | Module |
|-------------|-------|----------------|--------|
| Groth16 | BLS12-381 | Working | `zeroj-onchain-julc` |
| PlonK | BLS12-381 | Working | `zeroj-onchain-julc` |
| Groth16/PlonK | BN254 | Not feasible | No Plutus BN254 builtins |

The `zeroj-examples` module includes complete end-to-end tests (DSL to on-chain execution on Yaci DevKit).

## GraalVM Native Image

All modules include native-image configuration files in:
```
src/main/resources/META-INF/native-image/com.bloxbean.cardano/<module>/
```

Best-effort compatibility from the start; hardened in later milestones.

## Key ADRs

| ADR | Decision |
|-----|----------|
| [0001](adr/0001-verifier-first-architecture.md) | Verifier-first, no prover in core |
| [0002](adr/0002-external-proof-submission-first-class.md) | External proof submission as primary flow |
| [0003](adr/0003-pure-java-mvp.md) | Hybrid: blst for BLS12-381, pure Java for BN254 |
| [0004](adr/0004-off-chain-cardano-anchoring-first.md) | Off-chain Cardano anchoring first |
| [0005](adr/0005-plugin-provability-contract.md) | Explicit plugin provability contract |
| [0006](adr/0006-separation-of-crypto-and-policy-verification.md) | Separate crypto and policy verification |
| [0007](adr/0007-module-structure-and-boundaries.md) | Multi-module structure |
| [0008](adr/0008-plonk-support-via-gnark.md) | PlonK support via gnark |
| [0009](adr/0009-halo2-support-strategy.md) | Halo2 support strategy |
| [0010](adr/0010-java-circuit-dsl.md) | Java Circuit DSL |
