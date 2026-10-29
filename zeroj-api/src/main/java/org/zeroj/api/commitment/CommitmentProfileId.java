package org.zeroj.api.commitment;

import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * A registry identifier ({@code commitment-profiles-v1} §2.1): an ASCII string of 4 to 64 octets
 * whose entire content matches {@code [a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*}.
 *
 * <p>Identifiers compare octet for octet; there is no case folding, trimming or normalization.
 * Commitment profiles, proof protocols and basis sets share one namespace.
 */
public final class CommitmentProfileId {

    static final int MIN_LENGTH = 4;
    static final int MAX_LENGTH = 64;
    private static final Pattern GRAMMAR = Pattern.compile("[a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*");

    private final String value;

    private CommitmentProfileId(String value) {
        this.value = value;
    }

    /**
     * Validates and wraps an identifier.
     *
     * @throws NullPointerException       if {@code value} is null
     * @throws CommitmentFormatException  ({@code INVALID_CONFIGURATION}) if it is not a valid
     *                                    identifier
     */
    public static CommitmentProfileId of(String value) {
        Objects.requireNonNull(value, "value");
        // Length first, so the grammar never runs on an oversized input. Every character the
        // grammar admits is ASCII, so after a match the length in chars is the length in octets.
        if (value.length() < MIN_LENGTH || value.length() > MAX_LENGTH) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "identifier must be " + MIN_LENGTH + " to " + MAX_LENGTH + " octets");
        }
        // matches() is a whole-string match: "a-v1\n" is rejected.
        if (!GRAMMAR.matcher(value).matches()) {
            throw new CommitmentFormatException(CommitmentError.INVALID_CONFIGURATION,
                    "identifier does not match [a-z0-9]+(-[a-z0-9]+)*-v[1-9][0-9]*");
        }
        return new CommitmentProfileId(value);
    }

    /** The identifier string. */
    public String value() {
        return value;
    }

    /** A fresh copy of the identifier's ASCII octets. */
    public byte[] toAsciiBytes() {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CommitmentProfileId that && value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return value.hashCode();
    }

    @Override
    public String toString() {
        return value;
    }
}
