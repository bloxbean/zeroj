# ADR-0001: Verifier-First Architecture

## Status
Accepted

## Date
2026-03-25

## Context

ZeroJ aims to bring ZK capabilities to Cardano Java developers. ZK proof systems have two sides:
- **Proving**: generating a proof (computationally expensive, often requires native code, Rust/C libraries)
- **Verification**: checking a proof (relatively cheap, mathematically simpler, feasible in pure Java)

Building a full proving framework in Java is a multi-year effort and would compete with mature Rust ecosystems (snarkjs, arkworks, halo2). However, verification is orders of magnitude simpler and provides immediate value: Yaci nodes can verify externally generated proofs without recomputing.

## Decision

ZeroJ adopts a **verifier-first** architecture:

1. **Phase 1**: Pure Java verification of externally generated proofs (Groth16 on BN254/BLS12-381)
2. **Phase 2**: Sidecar-based proving (Java client calls external Rust/native prover service)
3. **Phase 3**: Optional native FFM bindings for in-process proving

The core public API is designed around the verification path:
- `ZkVerifier` interface is the primary SPI
- `ZkProofEnvelope` carries proof data from any source
- `VerificationResult` is the primary output type
- Proving is always behind a backend SPI, never in the core API

## Consequences

**Easier:**
- MVP ships faster with real value (verification)
- Pure Java means no JNI/FFM complexity in v1
- GraalVM native-image compatible from day one
- Yaci verifier-only nodes work immediately
- Compatible with any external prover ecosystem (snarkjs, circom, arkworks, gnark)

**Harder:**
- End-to-end demos require an external prover setup (snarkjs, etc.)
- Users who want proving must use a sidecar or external tool until Phase 2+
- Testing requires pre-generated proof fixtures (not a real problem — standard practice)

## Risks

- **Risk**: Users expect a batteries-included prover. **Mitigation**: Clear documentation, snarkjs integration guides, Docker sidecar from Milestone 7.
- **Risk**: Verification-only seems incomplete. **Mitigation**: This is the same model Ethereum L2s use — proofs are generated off-chain, verified on-chain/by nodes.
