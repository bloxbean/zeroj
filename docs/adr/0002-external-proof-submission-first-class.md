# ADR-0002: External Proof Submission as First-Class Flow

## Status
Accepted

## Date
2026-03-25

## Context

There are two models for how proofs enter the Yaci network:

1. **External submission**: An off-chain Java application computes, generates a proof (via snarkjs/arkworks/etc.), and submits the proof-backed state transition to a Yaci node.
2. **Plugin execution**: A Yaci node runs a plugin that computes and proves internally, then broadcasts to peers.

Both are valid, but external submission is simpler, more flexible, and covers the majority of real-world use cases (L2 rollups, off-chain computation verification, privacy-preserving state updates).

## Decision

External proof submission is the **primary** and **first implemented** submission model.

- `AppProofSubmission` is the canonical wire format for both external and plugin submissions
- The submission pipeline does not distinguish origin — it only cares about envelope validity
- External submitters authenticate via signature (Ed25519 or similar Cardano-compatible scheme)
- Plugin-based proving reuses the same envelope and verification pipeline
- No special "trusted" path for plugin-generated proofs — all proofs go through the same verification

## Consequences

**Easier:**
- Decouples prover technology from the verification network
- External teams can use any prover stack (Rust, Go, browser-based snarkjs)
- Simpler initial Yaci integration — no plugin lifecycle needed for MVP
- Same verification code path regardless of proof origin

**Harder:**
- External submitters need their own prover infrastructure
- Latency between proof generation and submission (not an issue for most use cases)

## Risks

- **Risk**: External submission without rate limiting could flood nodes. **Mitigation**: Submitter authorization + fee/deposit model in later milestone.
- **Risk**: Proof format incompatibility between different prover tools. **Mitigation**: Canonical encoding in zeroj-codec, clear format documentation, snarkjs compatibility as reference.
