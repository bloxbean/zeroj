# zeroj-patterns

High-level ZK patterns with typed inputs, enriched results, and pre-built verification policies.

This module provides opinionated, domain-specific APIs for the most common ZK use cases. Instead of working with raw proof envelopes, you work with typed domain objects (state transitions, nullifier claims, membership proofs) and get enriched results with additional computed fields.

## Patterns

### State Transition

Prove `new_state = f(old_state)` without revealing `f` or its inputs.

```java
// Prepare input
var input = StateTransitionInput.fromRawStates(oldState, newState, publicInputs);

// Attach externally generated proof
StateTransition transition = input.withProof(proofBytes, "my-circuit");

// Verify
var verifier = new StateTransitionVerifier(orchestrator);
StateTransitionResult result = verifier.verifyTransition(transition, material);

if (result.accepted()) {
    byte[] hash = result.transitionHash(); // SHA-256 of old+new roots, for anchoring
}
```

### Nullifier Claim

One-time claims with double-spend prevention.

```java
// Prepare claim
var input = NullifierClaimInput.of(claimant, claimValue, prevState, newState);
NullifierClaim claim = input.withProof(proofBytes, "claim-circuit");

// Verify
var verifier = new NullifierClaimVerifier(orchestrator);
ClaimResult result = verifier.verifyClaim(claim, material);

if (result.accepted()) {
    byte[] claimHash = result.claimHash(); // unique claim identifier
}
```

### Membership Proof

Prove set membership + constraints without revealing which element.

```java
// Prepare proof
var input = MembershipInput.of(element, merkleRoot, publicInputs);
MembershipProof proof = input.withProof(proofBytes, "membership-circuit");

// Verify
var verifier = new MembershipVerifier(orchestrator);
MembershipResult result = verifier.verifyMembership(proof, expectedRoot, material);
```

## Key Types

| Type | Description |
|------|-------------|
| `StateTransitionVerifier` | Verifies state transitions with root chain validation |
| `NullifierClaimVerifier` | Verifies one-time claims with nullifier tracking |
| `MembershipVerifier` | Verifies membership proofs with root matching |
| `PatternPolicies` | Pre-built policy validators for common rules |

Each pattern includes an `*Input` builder class, a domain object, and an enriched `*Result` record.

## Gradle

```gradle
dependencies {
    implementation 'com.bloxbean.cardano:zeroj-patterns'
}
```
