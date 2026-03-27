# ADR-0006: Separation of Cryptographic and Policy Verification

## Status
Accepted

## Date
2026-03-25

## Context

A proof can be cryptographically valid but still unacceptable. Consider:
- A valid Groth16 proof for the wrong circuit
- A valid proof with a stale previous state root
- A valid proof from an unauthorized submitter
- A valid proof with an already-used nullifier

Mixing cryptographic verification with protocol/policy checks in the same code leads to:
- Unclear failure reasons (was the proof bad or the policy violated?)
- Difficulty in testing each concern independently
- Coupling between the generic ZK library and submission-specific protocol logic

## Decision

The verification pipeline is explicitly split into two independent services:

### 1. ProofVerificationService (zeroj-verifier-core)
Responsible for:
- Resolving verification key from registry
- Delegating to the correct `ZkVerifier` backend
- Returning `CryptoVerificationResult` (valid/invalid + reason)

This service knows nothing about:
- State roots, sequences, nonces
- Submitter identity or authorization
- Application/plugin context
- Nullifiers or replay protection

### 2. SubmissionPolicyValidator (zeroj-ingestion)
Responsible for:
- Previous state root matches current accepted root
- Sequence/nonce is correct and not replayed
- Submitter is authorized (signature valid, in allowlist)
- Circuit version is allowed and not retired
- App/plugin is enabled
- Nullifier is unused
- Any custom policy hooks

This service does not perform cryptographic proof verification.

### Orchestration
The submission ingestion pipeline calls both in sequence:
1. Syntactic validation (envelope well-formed)
2. Signature/auth validation
3. Circuit/VK resolution
4. **Cryptographic verification** (ProofVerificationService)
5. **Protocol/policy validation** (SubmissionPolicyValidator)
6. Accept/reject

## Consequences

**Easier:**
- Clear, testable, single-responsibility services
- Generic ZK library (zeroj-*) is reusable standalone
- Policy rules can evolve independently of crypto verification
- Failure reasons are precise and actionable

**Harder:**
- Two services to maintain instead of one
- Must ensure consistent ordering in the pipeline

## Risks

- **Risk**: Performance — two separate services means two passes over some data. **Mitigation**: Verification is the expensive step; policy checks are cheap lookups. No meaningful overhead.
