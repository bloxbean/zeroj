package org.zeroj.api.commitment;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

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
    PROVENANCE_MISMATCH,
    /**
     * A prover was asked to prove a statement its proof protocol excludes, for
     * {@code bulletproof-range-bls12-381-g1-v1} an identity commitment. A prover refusal, never a
     * verdict on received data: it never appears in a {@link CommitmentCheck}. Appended after
     * {@link #PROVENANCE_MISMATCH} so that no earlier ordinal shifts (ADR-0061 D7a).
     */
    INVALID_STATEMENT;

    // An explicit set, not an ordinal range: INVALID_STATEMENT is a format class appended after the
    // two classes that are not (registry §11, ADR-0061 D7a).
    private static final Set<CommitmentError> FORMAT_CLASSES = Collections.unmodifiableSet(EnumSet.of(
            MALFORMED_ENCODING, NOT_IN_SUBGROUP, NON_CANONICAL_SCALAR, OUT_OF_RANGE, LENGTH_OUT_OF_RANGE,
            PROFILE_MISMATCH, INVALID_CONFIGURATION, INVALID_STATEMENT));

    /** {@code true} for the eight classes a {@link CommitmentFormatException} may carry. */
    boolean isFormatClass() {
        return FORMAT_CLASSES.contains(this);
    }

    /** {@code true} for the {@code PROVENANCE_*} classes. */
    boolean isProvenanceClass() {
        return this == PROVENANCE_MISSING || this == PROVENANCE_MISMATCH;
    }
}
