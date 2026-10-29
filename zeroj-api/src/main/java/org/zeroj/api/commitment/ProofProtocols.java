package org.zeroj.api.commitment;

/**
 * The descriptors of the built-in ZeroJ proof protocols ({@code commitment-profiles-v1} §5,
 * ADR-0061 D7a). Compare with {@code ==}.
 *
 * <p>A descriptor is configuration, not admission: a constant here for a protocol the registry still
 * lists as {@code reserved} does not make that protocol active.
 */
public final class ProofProtocols {

    /**
     * {@code bulletproof-range-bls12-381-g1-v1}: a range proof over {@code pedersen-bls12-381-g1-v1}
     * commitments, with the generator set {@code bulletproof-bls12-381-g1-gens-v1}.
     */
    public static final ProofProtocol BULLETPROOF_RANGE_BLS12_381_G1_V1 = ProofProtocol.BULLETPROOF_RANGE_BLS12_381_G1_V1;

    private ProofProtocols() {
    }
}
