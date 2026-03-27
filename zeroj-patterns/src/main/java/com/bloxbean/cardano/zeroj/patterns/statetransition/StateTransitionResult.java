package com.bloxbean.cardano.zeroj.patterns.statetransition;

import com.bloxbean.cardano.zeroj.api.VerificationResult;

import java.util.Objects;

/**
 * Result of a state transition verification — enriches {@link VerificationResult}
 * with transition-specific metadata for Cardano anchoring.
 * <p>
 * Example:
 * <pre>{@code
 * StateTransitionResult result = verifier.verifyTransition(transition, material);
 * if (result.accepted()) {
 *     byte[] anchor = result.transitionHash();  // deterministic hash for on-chain anchoring
 * }
 * }</pre>
 *
 * @param verificationResult the underlying cryptographic verification result
 * @param transitionHash     deterministic hash of the transition (for anchoring)
 * @param oldStateHash       the old state hash that was verified
 * @param newStateHash       the new state hash that was verified
 */
public record StateTransitionResult(
        VerificationResult verificationResult,
        byte[] transitionHash,
        byte[] oldStateHash,
        byte[] newStateHash
) {
    public StateTransitionResult {
        Objects.requireNonNull(verificationResult);
        transitionHash = transitionHash != null ? transitionHash.clone() : null;
        oldStateHash = oldStateHash != null ? oldStateHash.clone() : null;
        newStateHash = newStateHash != null ? newStateHash.clone() : null;
    }

    @Override public byte[] transitionHash() { return transitionHash != null ? transitionHash.clone() : null; }
    @Override public byte[] oldStateHash() { return oldStateHash != null ? oldStateHash.clone() : null; }
    @Override public byte[] newStateHash() { return newStateHash != null ? newStateHash.clone() : null; }

    /** Whether the transition was verified (cryptographically valid). */
    public boolean accepted() { return verificationResult.proofValid(); }

    /** Whether the proof was cryptographically valid (before policy checks). */
    public boolean proofValid() { return verificationResult.proofValid(); }

    static StateTransitionResult from(VerificationResult result, StateTransition transition) {
        return new StateTransitionResult(result,
                transition.transitionHash(), transition.oldStateHash(), transition.newStateHash());
    }
}
