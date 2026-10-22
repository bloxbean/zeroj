package org.zeroj.api.commitment;

/**
 * The descriptors of the built-in ZeroJ commitment profiles ({@code commitment-profiles-v1} §12.1,
 * ADR-0060 D8). Compare with {@code ==}.
 *
 * <p>They are created and registered while {@link CommitmentProfile} is initialised, so they exist
 * before any caller can reach {@link CommitmentProfile#define}, and a {@code define} of a built-in
 * identifier is always rejected. The profile modules publish these same instances as their
 * {@code PROFILE} constants.
 *
 * <p>A descriptor is configuration, not admission: a constant here for a profile the registry still
 * lists as {@code reserved} does not make that profile active (ADR-0060 D1).
 */
public final class CommitmentProfiles {

    /** {@code pedersen-jubjub-v1}: scalar, Jubjub, 32-octet points. */
    public static final CommitmentProfile PEDERSEN_JUBJUB_V1 = CommitmentProfile.PEDERSEN_JUBJUB_V1;

    /** {@code pedersen-jubjub-bytes-v1}: bytes, Jubjub, 32-octet points. */
    public static final CommitmentProfile PEDERSEN_JUBJUB_BYTES_V1 = CommitmentProfile.PEDERSEN_JUBJUB_BYTES_V1;

    /** {@code pedersen-jubjub-vector-v1}: vector, Jubjub, 32-octet points. */
    public static final CommitmentProfile PEDERSEN_JUBJUB_VECTOR_V1 = CommitmentProfile.PEDERSEN_JUBJUB_VECTOR_V1;

    /** {@code pedersen-bls12-381-g1-v1}: scalar, BLS12-381 G1, 48-octet points. */
    public static final CommitmentProfile PEDERSEN_BLS12_381_G1_V1 = CommitmentProfile.PEDERSEN_BLS12_381_G1_V1;

    /** {@code pedersen-bls12-381-g1-bytes-v1}: bytes, BLS12-381 G1, 48-octet points. */
    public static final CommitmentProfile PEDERSEN_BLS12_381_G1_BYTES_V1 =
            CommitmentProfile.PEDERSEN_BLS12_381_G1_BYTES_V1;

    private CommitmentProfiles() {
    }
}
