package com.bloxbean.cardano.zeroj.patterns.nullifier;

import com.bloxbean.cardano.zeroj.api.VerificationResult;

import java.util.Objects;

/**
 * Result of a nullifier claim verification — enriches {@link VerificationResult}
 * with claim-specific metadata.
 * <p>
 * Example:
 * <pre>{@code
 * ClaimResult result = verifier.verifyAndAcceptClaim(claim, material);
 * if (result.accepted()) {
 *     // claim was valid and nullifier is now marked as spent
 * } else if (result.nullifierAlreadySpent()) {
 *     // double-claim attempt detected
 * }
 * }</pre>
 *
 * @param verificationResult  the underlying verification result
 * @param nullifierAlreadySpent true if the nullifier was already used
 */
public record ClaimResult(
        VerificationResult verificationResult,
        boolean nullifierAlreadySpent
) {
    public ClaimResult {
        Objects.requireNonNull(verificationResult);
    }

    /** Whether the claim was accepted (proof valid + nullifier fresh). */
    public boolean accepted() { return verificationResult.proofValid() && !nullifierAlreadySpent; }

    /** Whether the proof was cryptographically valid (before nullifier check). */
    public boolean proofValid() { return verificationResult.proofValid(); }

    static ClaimResult accepted(VerificationResult result) {
        return new ClaimResult(result, false);
    }

    static ClaimResult doubleSpend() {
        return new ClaimResult(
                VerificationResult.policyRejected(
                        VerificationResult.ReasonCode.USED_NULLIFIER,
                        "Nullifier already used"),
                true);
    }

    static ClaimResult proofFailed(VerificationResult result) {
        return new ClaimResult(result, false);
    }
}
