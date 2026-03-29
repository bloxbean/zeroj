# ADR-0007: Multi-Module Structure and Boundaries

## Status
Accepted

## Date
2026-03-25

## Context

ZeroJ serves three distinct audiences:
1. **Java developers** who want a standalone ZK verification library (no Cardano dependency)
2. **Network operators** who want proof-verified app-layer consensus
3. **Cardano dApp developers** who want to anchor ZK results on L1

The module structure must allow each audience to depend on only what they need.

## Decision

### Core Modules (top-level)

#### Layer 1: Core ZK Library (standalone, no Cardano dependency)

| Module | Purpose |
|--------|---------|
| `zeroj-api` | Proof model, verifier interfaces, result types, enums |
| `zeroj-codec` | JSON/CBOR serialization, canonical hashing, envelope validation |
| `zeroj-backend-spi` | `ZkVerifier` SPI, `VerificationKeyRegistry`, `CircuitRegistry`, backend discovery |
| `zeroj-verifier-core` | Orchestration, verifier registry, prepared key cache |
| `zeroj-verifier-groth16` | Groth16 verification backend (BN254 + BLS12-381 pure Java) |
| `zeroj-verifier-plonk` | PlonK verification backend (BN254 + BLS12-381 pure Java) |
| `zeroj-blst` | BLS12-381 pairing operations via blst native library |

#### Layer 2: Circuit Definition

| Module | Purpose |
|--------|---------|
| `zeroj-circuit-dsl` | Java Circuit DSL -- define circuits, compile to R1CS/PlonK/Halo2 |
| `zeroj-circuit-lib` | Circuit standard library -- Poseidon, MiMC, Merkle, comparators |

#### Layer 3: Proving

| Module | Purpose |
|--------|---------|
| `zeroj-prover-gnark` | gnark native Groth16/PlonK prover via Go FFM (primary) |

#### Layer 4: Submission & Ingestion

| Module | Purpose |
|--------|---------|
| `zeroj-submission` | `AppProofSubmission` wire format, sequence model, submitter signature |
| `zeroj-ingestion` | Submission pipeline, state-root validation, replay protection, policy validator |

#### Layer 5: Cardano Integration

| Module | Purpose |
|--------|---------|
| `zeroj-cardano` | Anchor model, metadata encoding, datum helpers |
| `zeroj-ccl` | CCL transaction builder integration, fluent anchoring API |
| `zeroj-onchain-julc` | Reusable Plutus V3 Groth16/PlonK validators via Julc |

#### Layer 6: High-Level APIs & Infrastructure

| Module | Purpose |
|--------|---------|
| `zeroj-patterns` | State transition, nullifier claim, membership proof APIs |
| `zeroj-test-vectors` | Shared test fixtures (not published) |
| `zeroj-examples` | End-to-end demos (not published) |
| `zeroj-bom` | Bill of Materials for version alignment |

### Incubator Modules (`incubator/`)

Experimental and alternative backends. Still compiled, tested, and published, but visually separated.

| Module | Purpose |
|--------|---------|
| `zeroj-prover-rapidsnark` | RapidSNARK native BN254 Groth16 prover via FFM |
| `zeroj-prover-sidecar` | HTTP client SDK for external prover sidecar service |
| `zeroj-prover-wasm` | Circom witness calculation via GraalVM WebAssembly |
| `zeroj-verifier-halo2` | Halo2 IPA verification via Rust FFM |
| `zeroj-onchain-experimental` | On-chain helpers -- proof preparation, budget estimation |

### Dependency Rules

```
zeroj-api          <-- everything depends on this
zeroj-codec        <-- depends on zeroj-api
zeroj-backend-spi  <-- depends on zeroj-api
zeroj-verifier-core <-- depends on zeroj-api, zeroj-backend-spi
zeroj-verifier-groth16 <-- depends on zeroj-backend-spi

zeroj-submission    <-- depends on zeroj-api, zeroj-codec
zeroj-ingestion     <-- depends on zeroj-submission, zeroj-verifier-core

zeroj-cardano       <-- depends on zeroj-api, zeroj-codec
zeroj-ccl           <-- depends on zeroj-cardano, cardano-client-lib
```

**No circular dependencies. Submission/ingestion modules do not depend on Cardano modules or vice versa.**

### Package Naming

All packages: `com.bloxbean.cardano.zeroj.<module-suffix>`

Examples:
- `com.bloxbean.cardano.zeroj.api`
- `com.bloxbean.cardano.zeroj.codec`
- `com.bloxbean.cardano.zeroj.verifier.groth16`
- `com.bloxbean.cardano.zeroj.submission`
- `com.bloxbean.cardano.zeroj.cardano`

## Consequences

**Easier:**
- Each audience pulls only what they need
- Clean separation allows parallel development
- Core ZK library is usable outside Cardano ecosystem
- Testing each layer independently is straightforward

**Harder:**
- More modules = more Gradle configuration
- Cross-module refactoring requires care
- Version alignment across modules

## Risks

- **Risk**: Too many modules for a small team. **Mitigation**: Start with core modules only (Milestones 0-2 = 5 modules). Add submission/Cardano modules as needed. Empty modules are cheap.
- **Risk**: Module boundaries may shift as we learn. **Mitigation**: ADRs are living documents. Module merges/splits are fine if the public API is stable.
