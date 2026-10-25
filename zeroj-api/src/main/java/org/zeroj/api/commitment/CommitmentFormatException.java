package org.zeroj.api.commitment;

import java.io.Serial;
import java.util.Objects;

/**
 * A rejected commitment input on a strict path ({@code commitment-profiles-v1} §11).
 *
 * <p>Extends {@link IllegalArgumentException}, so callers that already catch it keep working. It
 * carries only the eight format classes, {@link CommitmentError#MALFORMED_ENCODING} through
 * {@link CommitmentError#INVALID_CONFIGURATION} and {@link CommitmentError#INVALID_STATEMENT}; an
 * opening mismatch is a {@code false} result and provenance outcomes exist only in
 * {@link CommitmentCheck}. It retains no secret value, and
 * callers must never put one in the message.
 */
public final class CommitmentFormatException extends IllegalArgumentException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final CommitmentError reason;

    /**
     * @param reason  one of the eight format classes
     * @param message a description that contains no secret value
     * @throws NullPointerException     if {@code reason} is null
     * @throws IllegalArgumentException if {@code reason} is {@code OPENING_MISMATCH} or a
     *                                  {@code PROVENANCE_*} class
     */
    public CommitmentFormatException(CommitmentError reason, String message) {
        super(checked(reason) + ": " + message);
        this.reason = reason;
    }

    /** The error class. */
    public CommitmentError reason() {
        return reason;
    }

    private static CommitmentError checked(CommitmentError reason) {
        Objects.requireNonNull(reason, "reason");
        if (!reason.isFormatClass()) {
            throw new IllegalArgumentException(reason + " is not a format error class");
        }
        return reason;
    }
}
