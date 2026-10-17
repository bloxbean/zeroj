package org.zeroj.api.commitment;

/**
 * The expected profile, as the caller's trusted configuration states it
 * ({@code commitment-profiles-v1} §12.1). Every decoder takes one; none selects a profile from
 * data.
 *
 * @param <C> the profile's concrete commitment type
 */
public interface CommitmentCodec<C extends Commitment> {

    /** The expected profile's descriptor. */
    CommitmentProfile profile();

    /** The exact concrete class of this profile's commitments. */
    Class<C> commitmentType();

    /**
     * Strictly decodes the profile's raw point encoding (spec §10). Never returns null.
     *
     * @throws NullPointerException      if {@code pointBytes} is null
     * @throws CommitmentFormatException ({@code MALFORMED_ENCODING} or {@code NOT_IN_SUBGROUP})
     */
    C decodePoint(byte[] pointBytes);

    /**
     * Context octets that {@link CommitmentKey} appends to the identifier and point: empty by
     * default; the vector codec returns its schema digest. Returns a fresh array.
     */
    default byte[] keyContext() {
        return new byte[0];
    }

    /**
     * Rejects a commitment whose context differs from this codec's: a no-op by default; the vector
     * codec rejects a different schema.
     *
     * @throws CommitmentFormatException ({@code PROFILE_MISMATCH})
     */
    default void requireContext(C commitment) {
    }
}
