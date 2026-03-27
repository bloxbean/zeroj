package com.bloxbean.cardano.zeroj.patterns.membership;

import com.bloxbean.cardano.zeroj.api.VerificationResult;

import java.util.Objects;

/**
 * Result of a membership proof verification — enriches {@link VerificationResult}
 * with membership-specific metadata.
 * <p>
 * Example:
 * <pre>{@code
 * MembershipResult result = verifier.verifyMembership(proof, expectedRoot, material);
 * if (result.accepted()) {
 *     // member is in the set and satisfies constraints
 * } else if (!result.rootMatched()) {
 *     // proof is for a different/stale set
 * }
 * }</pre>
 *
 * @param verificationResult the underlying verification result
 * @param rootMatched        whether the proof's Merkle root matches the expected root
 */
public record MembershipResult(
        VerificationResult verificationResult,
        boolean rootMatched
) {
    public MembershipResult {
        Objects.requireNonNull(verificationResult);
    }

    /** Whether the membership was verified (proof valid + root matched). */
    public boolean accepted() { return verificationResult.proofValid() && rootMatched; }

    /** Whether the proof was cryptographically valid (before root check). */
    public boolean proofValid() { return verificationResult.proofValid(); }

    static MembershipResult rootMismatch() {
        return new MembershipResult(
                VerificationResult.policyRejected(
                        VerificationResult.ReasonCode.STALE_STATE_ROOT,
                        "Merkle root does not match expected root"),
                false);
    }

    static MembershipResult from(VerificationResult result) {
        return new MembershipResult(result, true);
    }
}
