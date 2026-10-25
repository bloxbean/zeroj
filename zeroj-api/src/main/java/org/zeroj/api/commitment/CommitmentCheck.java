package org.zeroj.api.commitment;

import java.util.Optional;

/**
 * The outcome of {@link CommitmentAcceptance#accept} ({@code commitment-profiles-v1} §12.1).
 *
 * <p>There is no public factory: only {@code CommitmentAcceptance} creates one, so no caller can
 * fabricate an accepted result. The reason never contains a secret value.
 */
public final class CommitmentCheck {

    private static final CommitmentCheck ACCEPTED = new CommitmentCheck(null);

    private final CommitmentError reason;

    private CommitmentCheck(CommitmentError reason) {
        this.reason = reason;
    }

    static CommitmentCheck acceptedCheck() {
        return ACCEPTED;
    }

    static CommitmentCheck rejected(CommitmentError reason) {
        if (reason == null) {
            throw new NullPointerException("reason");
        }
        // A prover refusal is never a verdict on received data (spec §11).
        if (reason == CommitmentError.INVALID_STATEMENT) {
            throw new IllegalArgumentException("INVALID_STATEMENT never appears in a CommitmentCheck");
        }
        return new CommitmentCheck(reason);
    }

    /** {@code true} iff decoding, provenance and the opening all succeeded. */
    public boolean accepted() {
        return reason == null;
    }

    /** The first failure; empty iff {@link #accepted()}. */
    public Optional<CommitmentError> reason() {
        return Optional.ofNullable(reason);
    }

    /**
     * {@code true} iff the commitment was rejected by application policy (a {@code PROVENANCE_*}
     * class) rather than by a cryptographic or format check.
     */
    public boolean policyRejected() {
        return reason != null && reason.isProvenanceClass();
    }

    @Override
    public String toString() {
        return reason == null ? "CommitmentCheck[accepted]" : "CommitmentCheck[rejected: " + reason + "]";
    }
}
