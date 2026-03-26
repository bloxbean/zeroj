package com.bloxbean.cardano.zeroj.codec;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Parsed representation of a snarkjs Groth16 proof.json file.
 *
 * <p>Curve points are represented as lists of {@link BigInteger} coordinates.
 * G1 points: [x, y, z] (projective). G2 points: [[x0,x1],[y0,y1],[z0,z1]] (Fp2 projective).</p>
 *
 * @param piA      G1 point [x, y, z]
 * @param piB      G2 point [[x0,x1],[y0,y1],[z0,z1]]
 * @param piC      G1 point [x, y, z]
 * @param protocol proof system identifier (e.g., "groth16")
 * @param curve    curve identifier (e.g., "bn128", "bls12381")
 */
public record SnarkjsProof(
        List<BigInteger> piA,
        List<List<BigInteger>> piB,
        List<BigInteger> piC,
        String protocol,
        String curve
) {

    public SnarkjsProof {
        Objects.requireNonNull(piA, "pi_a must not be null");
        Objects.requireNonNull(piB, "pi_b must not be null");
        Objects.requireNonNull(piC, "pi_c must not be null");
        Objects.requireNonNull(protocol, "protocol must not be null");
        Objects.requireNonNull(curve, "curve must not be null");
        piA = List.copyOf(piA);
        piB = piB.stream().map(List::copyOf).toList();
        piC = List.copyOf(piC);
        if (piA.size() != 3) {
            throw new IllegalArgumentException("pi_a must have 3 coordinates, got " + piA.size());
        }
        if (piB.size() != 3) {
            throw new IllegalArgumentException("pi_b must have 3 coordinate pairs, got " + piB.size());
        }
        for (int i = 0; i < piB.size(); i++) {
            if (piB.get(i).size() != 2) {
                throw new IllegalArgumentException("pi_b[" + i + "] must have 2 elements, got " + piB.get(i).size());
            }
        }
        if (piC.size() != 3) {
            throw new IllegalArgumentException("pi_c must have 3 coordinates, got " + piC.size());
        }
    }
}
