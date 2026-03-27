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

### Layer 1: Core ZK Library (standalone, no Cardano dependency)

| Module | Purpose |
|--------|---------|
| `zeroj-api` | Proof model, verifier interfaces, result types, enums |
| `zeroj-codec` | JSON/CBOR serialization, canonical hashing, envelope validation |
| `zeroj-backend-spi` | `ZkVerifier` SPI, `VerificationKeyRegistry`, `CircuitRegistry`, backend discovery |
| `zeroj-verifier-core` | Orchestration, verifier registry, prepared key cache |
| `zeroj-verifier-groth16` | Groth16 verification backend (BN254 + BLS12-381 pure Java) |

### Layer 2: Submission & Ingestion

| Module | Purpose |
|--------|---------|
| `zeroj-submission` | `AppProofSubmission` wire format, sequence model, submitter signature |
| `zeroj-ingestion` | Submission pipeline, state-root validation, replay protection, policy validator |

### Layer 3: Cardano Integration

| Module | Purpose |
|--------|---------|
| `zeroj-cardano` | Anchor model, metadata encoding, datum helpers |
| `zeroj-ccl` | CCL transaction builder integration, fluent anchoring API |

### Layer 4: Extended (later milestones)

| Module | Purpose |
|--------|---------|
| `zeroj-prover-sidecar-client` | Client SDK for external prover sidecar service |
| `zeroj-ffi` | Java 25 FFM bindings to native backends |
| `zeroj-verifier-plonk` | PlonK verification backend |
| `zeroj-onchain-experimental` | Plutus/Aiken on-chain verifier experiments |

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
