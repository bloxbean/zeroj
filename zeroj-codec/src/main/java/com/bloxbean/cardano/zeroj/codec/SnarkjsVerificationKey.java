package com.bloxbean.cardano.zeroj.codec;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Parsed representation of a snarkjs Groth16 verification_key.json file.
 *
 * @param protocol     proof system identifier (e.g., "groth16")
 * @param curve        curve identifier (e.g., "bn128", "bls12381")
 * @param nPublic      number of public inputs
 * @param vkAlpha1     G1 point [x, y, z]
 * @param vkBeta2      G2 point [[x0,x1],[y0,y1],[z0,z1]]
 * @param vkGamma2     G2 point
 * @param vkDelta2     G2 point
 * @param vkAlphabeta12 pre-computed pairing result (GT element, 2x3x2 nested array)
 * @param ic           array of G1 points for public input linear combination
 */
public record SnarkjsVerificationKey(
        String protocol,
        String curve,
        int nPublic,
        List<BigInteger> vkAlpha1,
        List<List<BigInteger>> vkBeta2,
        List<List<BigInteger>> vkGamma2,
        List<List<BigInteger>> vkDelta2,
        List<List<List<BigInteger>>> vkAlphabeta12,
        List<List<BigInteger>> ic
) {

    public SnarkjsVerificationKey {
        Objects.requireNonNull(protocol, "protocol must not be null");
        Objects.requireNonNull(curve, "curve must not be null");
        Objects.requireNonNull(vkAlpha1, "vk_alpha_1 must not be null");
        Objects.requireNonNull(vkBeta2, "vk_beta_2 must not be null");
        Objects.requireNonNull(vkGamma2, "vk_gamma_2 must not be null");
        Objects.requireNonNull(vkDelta2, "vk_delta_2 must not be null");
        Objects.requireNonNull(vkAlphabeta12, "vk_alphabeta_12 must not be null");
        Objects.requireNonNull(ic, "IC must not be null");
        if (nPublic < 0) {
            throw new IllegalArgumentException("nPublic must be >= 0, got " + nPublic);
        }
        // IC should have nPublic + 1 entries
        if (ic.size() != nPublic + 1) {
            throw new IllegalArgumentException("IC must have " + (nPublic + 1) + " entries for " + nPublic + " public inputs, got " + ic.size());
        }
        vkAlpha1 = List.copyOf(vkAlpha1);
        vkBeta2 = vkBeta2.stream().map(List::copyOf).toList();
        vkGamma2 = vkGamma2.stream().map(List::copyOf).toList();
        vkDelta2 = vkDelta2.stream().map(List::copyOf).toList();
        vkAlphabeta12 = vkAlphabeta12.stream()
                .map(l -> l.stream().map(List::copyOf).toList())
                .toList();
        ic = ic.stream().map(List::copyOf).toList();
    }
}
