package com.bloxbean.cardano.zeroj.submission;

import java.util.Objects;
import java.util.Optional;

/**
 * Result of the submission ingestion pipeline.
 *
 * <p>Records which validation stage failed (if any) and provides a reason.</p>
 *
 * @param accepted whether the submission was accepted
 * @param stage    the validation stage that produced this result
 * @param reason   machine-readable rejection reason (empty if accepted)
 * @param message  human-readable description
 */
public record SubmissionResult(
        boolean accepted,
        ValidationStage stage,
        Optional<RejectionReason> reason,
        Optional<String> message
) {

    public SubmissionResult {
        Objects.requireNonNull(stage);
        Objects.requireNonNull(reason);
        Objects.requireNonNull(message);
    }

    public static SubmissionResult ok() {
        return new SubmissionResult(true, ValidationStage.ACCEPTED, Optional.empty(), Optional.empty());
    }

    public static SubmissionResult rejected(ValidationStage stage, RejectionReason reason, String message) {
        return new SubmissionResult(false, stage, Optional.of(reason), Optional.ofNullable(message));
    }

    /**
     * The validation stages in the ingestion pipeline, in execution order.
     */
    public enum ValidationStage {
        SYNTACTIC,
        SIGNATURE,
        CIRCUIT_RESOLUTION,
        CRYPTOGRAPHIC_VERIFICATION,
        POLICY,
        ACCEPTED
    }

    /**
     * Machine-readable rejection reasons.
     */
    public enum RejectionReason {
        // Syntactic
        MALFORMED_SUBMISSION,
        EMPTY_PROOF,
        INVALID_VK_HASH_LENGTH,

        // Signature
        INVALID_SIGNATURE,
        UNKNOWN_SUBMITTER,
        UNAUTHORIZED_SUBMITTER,
        SUBMITTER_SUSPENDED,

        // Circuit resolution
        UNKNOWN_CIRCUIT,
        DEPRECATED_CIRCUIT,
        RETIRED_CIRCUIT,
        VK_NOT_FOUND,
        VK_EXPIRED,

        // Cryptographic
        PROOF_INVALID,
        PROOF_VERIFICATION_ERROR,

        // Policy
        STALE_STATE_ROOT,
        DUPLICATE_SEQUENCE,
        USED_NULLIFIER,
        SEQUENCE_GAP
    }
}
