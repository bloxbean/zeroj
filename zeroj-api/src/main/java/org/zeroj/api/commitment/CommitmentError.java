package org.zeroj.api.commitment;

/**
 * The error classes of {@code commitment-profiles-v1} §11. Every strict path reports exactly the
 * class the specification assigns; on-chain, every class is a script failure.
 */
public enum CommitmentError {
    /** A structural, length or curve-encoding defect. */
    MALFORMED_ENCODING,
    /** A valid curve point outside the prime-order subgroup. */
    NOT_IN_SUBGROUP,
    /** Check 1 failed: a scalar outside {@code [0, q)}. */
    NON_CANONICAL_SCALAR,
    /** Check 2 (amount bound) or check 3 (vector bound policy) failed. */
    OUT_OF_RANGE,
    /** A {@code bytes} declared length or maximum outside {@code [0, MAX_PAYLOAD_BYTES]}. */
    LENGTH_OUT_OF_RANGE,
    /** A label, codec, class, descriptor or schema other than the expected one. */
    PROFILE_MISMATCH,
    /**
     * An invalid identifier string, amount-bound width, bound policy, descriptor point-encoding
     * length or duplicate descriptor.
     */
    INVALID_CONFIGURATION,
    /** A well-formed opening that does not satisfy the commitment equation. */
    OPENING_MISMATCH,
    /** The application has no authenticated issuance record. */
    PROVENANCE_MISSING,
    /** The issuance record does not bind this point, profile and context. */
    PROVENANCE_MISMATCH;

    /** {@code true} for the seven classes a {@link CommitmentFormatException} may carry. */
    boolean isFormatClass() {
        return ordinal() <= INVALID_CONFIGURATION.ordinal();
    }

    /** {@code true} for the {@code PROVENANCE_*} classes. */
    boolean isProvenanceClass() {
        return this == PROVENANCE_MISSING || this == PROVENANCE_MISMATCH;
    }
}
