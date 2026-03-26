package com.bloxbean.cardano.zeroj.api;

import java.util.Objects;
import java.util.Optional;

/**
 * Result of proof verification — separates cryptographic validity from policy validity.
 *
 * <p>A proof can be cryptographically valid but rejected by policy (e.g., stale state root,
 * unauthorized submitter). This type captures both dimensions.</p>
 *
 * @param proofValid    whether the cryptographic proof verification passed
 * @param protocolValid whether the protocol/policy checks passed (empty if not evaluated)
 * @param accepted      overall acceptance — true only if both proof and protocol are valid
 * @param reasonCode    machine-readable reason code for rejection (empty if accepted)
 * @param message       human-readable description (empty if accepted)
 */
public record VerificationResult(
        boolean proofValid,
        Optional<Boolean> protocolValid,
        boolean accepted,
        Optional<ReasonCode> reasonCode,
        Optional<String> message
) {

    public VerificationResult {
        Objects.requireNonNull(protocolValid, "protocolValid must not be null");
        Objects.requireNonNull(reasonCode, "reasonCode must not be null");
        Objects.requireNonNull(message, "message must not be null");
    }

    /**
     * Create a successful verification result (proof valid, accepted).
     */
    public static VerificationResult ok() {
        return new VerificationResult(true, Optional.of(true), true, Optional.empty(), Optional.empty());
    }

    /**
     * Create a result where the cryptographic proof is valid but protocol checks haven't been run.
     */
    public static VerificationResult cryptoValid() {
        return new VerificationResult(true, Optional.empty(), false, Optional.empty(), Optional.empty());
    }

    /**
     * Create a rejection due to invalid cryptographic proof.
     */
    public static VerificationResult proofInvalid(String message) {
        return new VerificationResult(false, Optional.empty(), false,
                Optional.of(ReasonCode.INVALID_PROOF), Optional.ofNullable(message));
    }

    /**
     * Create a rejection due to policy/protocol failure (proof was cryptographically valid).
     */
    public static VerificationResult policyRejected(ReasonCode reason, String message) {
        return new VerificationResult(true, Optional.of(false), false,
                Optional.of(reason), Optional.ofNullable(message));
    }

    /**
     * Create a rejection due to a processing error.
     */
    public static VerificationResult error(ReasonCode reason, String message) {
        return new VerificationResult(false, Optional.empty(), false,
                Optional.of(reason), Optional.ofNullable(message));
    }

    /**
     * Machine-readable reason codes for verification rejection.
     */
    public enum ReasonCode {
        INVALID_PROOF,
        INVALID_PUBLIC_INPUTS,
        UNKNOWN_CIRCUIT,
        UNKNOWN_VERIFICATION_KEY,
        VK_MISMATCH,
        UNSUPPORTED_PROOF_SYSTEM,
        UNSUPPORTED_CURVE,
        MALFORMED_ENVELOPE,
        STALE_STATE_ROOT,
        DUPLICATE_NONCE,
        UNAUTHORIZED_SUBMITTER,
        RETIRED_CIRCUIT,
        USED_NULLIFIER,
        INTERNAL_ERROR
    }
}
