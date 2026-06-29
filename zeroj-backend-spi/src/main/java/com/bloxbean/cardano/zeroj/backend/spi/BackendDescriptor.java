package com.bloxbean.cardano.zeroj.backend.spi;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

/**
 * Declares what proof system and curve a {@link ZkVerifier} backend supports.
 *
 * @param proofSystem the proof system (e.g., GROTH16)
 * @param curve       the elliptic curve (e.g., BLS12_381)
 * @param name        human-readable backend name (e.g., "groth16-bls12381-java")
 */
public record BackendDescriptor(
        ProofSystemId proofSystem,
        CurveId curve,
        String name
) {

    /**
     * Check if this backend can handle the given proof system and curve combination.
     */
    public boolean supports(ProofSystemId proofSystem, CurveId curve) {
        return this.proofSystem == proofSystem && this.curve == curve;
    }
}
