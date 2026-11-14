package org.zeroj.api.commitment;

import java.io.IOException;
import java.util.Objects;

/**
 * Decoding, provenance and opening in one call ({@code commitment-profiles-v1} §12.1).
 *
 * <p>Acceptance establishes what the opening check establishes, under the expected profile and the
 * application's provenance rule. Authorization, replay protection and context binding remain the
 * application's.
 *
 * <p><b>Timing.</b> This class adds no arithmetic, but the opening check usually runs a
 * variable-time disclosed verification (class V1). Disclosed is not public: run it only where the
 * opening is already public or no party from whom it is still secret can observe the verifier's
 * timing; otherwise run the whole acceptance offline or in an isolated process
 * ({@code commitment-profiles-v1} §6.2, ADR-0059 A2).
 */
public final class CommitmentAcceptance {

    private CommitmentAcceptance() {
    }

    /**
     * Accepts if and only if, in this order, the envelope decodes under {@code expected} (spec §9,
     * including the class and descriptor check), {@code provenance.check} returns exactly
     * {@link ProvenancePolicy.Result#OK}, and {@code opening.matches} returns {@code true}.
     * Otherwise returns the first failure:
     * <ul>
     *   <li>a {@link CommitmentFormatException} from decoding, or from the opening check with a
     *       reason other than {@code INVALID_CONFIGURATION} or {@code INVALID_STATEMENT} → its
     *       reason;</li>
     *   <li>{@code MISSING} → {@code PROVENANCE_MISSING}; {@code MISMATCH} →
     *       {@code PROVENANCE_MISMATCH};</li>
     *   <li>{@code false} → {@code OPENING_MISMATCH}.</li>
     * </ul>
     *
     * <p>Every other throwable propagates unchanged, including any exception from the provenance
     * callback and an {@code INVALID_CONFIGURATION} from the opening check (a verifier
     * misconfiguration, not a data verdict). A {@code CommitmentFormatException} with
     * {@code INVALID_STATEMENT} propagates unchanged from every step: it is a prover refusal, never a
     * verdict on received data, so it never becomes a {@link CommitmentCheck} (spec §11, §12.1). No
     * path turns a failure into acceptance.
     *
     * @throws NullPointerException if an argument is null, or the provenance callback returns null
     * @throws IOException          if the opening check throws it
     */
    public static <C extends Commitment> CommitmentCheck accept(byte[] envelope, CommitmentCodec<C> expected,
                                                                ProvenancePolicy<? super C> provenance,
                                                                OpeningCheck<? super C> opening) throws IOException {
        Objects.requireNonNull(envelope, "envelope");
        Objects.requireNonNull(expected, "expected");
        Objects.requireNonNull(provenance, "provenance");
        Objects.requireNonNull(opening, "opening");

        C commitment;
        try {
            commitment = CommitmentEnvelope.decode(envelope, expected);
        } catch (CommitmentFormatException e) {
            if (e.reason() == CommitmentError.INVALID_STATEMENT) {
                throw e;
            }
            return CommitmentCheck.rejected(e.reason());
        }

        // Exceptions from the callback propagate: this step maps results, not throwables.
        ProvenancePolicy.Result result = Objects.requireNonNull(provenance.check(commitment), "provenance result");
        // An exhaustive switch expression: a constant added later fails here instead of falling
        // through to the opening check.
        CommitmentError provenanceFailure = switch (result) {
            case OK -> null;
            case MISSING -> CommitmentError.PROVENANCE_MISSING;
            case MISMATCH -> CommitmentError.PROVENANCE_MISMATCH;
        };
        if (provenanceFailure != null) {
            return CommitmentCheck.rejected(provenanceFailure);
        }

        boolean matches;
        try {
            matches = opening.matches(commitment);
        } catch (CommitmentFormatException e) {
            if (e.reason() == CommitmentError.INVALID_CONFIGURATION
                    || e.reason() == CommitmentError.INVALID_STATEMENT) {
                throw e;
            }
            return CommitmentCheck.rejected(e.reason());
        }
        return matches ? CommitmentCheck.acceptedCheck() : CommitmentCheck.rejected(CommitmentError.OPENING_MISMATCH);
    }
}
