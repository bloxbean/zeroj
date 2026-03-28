package com.bloxbean.cardano.zeroj.verifier.plonk;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Parsed PlonK proof structure.
 *
 * <p>Contains the commitments and evaluation openings from the prover.
 * For snarkjs PlonK, the proof contains BN254 or BLS12-381 curve points
 * and scalar evaluations at the challenge point zeta.</p>
 *
 * @param cmA             commitment to left wire polynomial (G1 point)
 * @param cmB             commitment to right wire polynomial (G1 point)
 * @param cmC             commitment to output wire polynomial (G1 point)
 * @param cmZ             commitment to grand product polynomial (G1 point)
 * @param cmT1            commitment to quotient polynomial part 1 (G1 point)
 * @param cmT2            commitment to quotient polynomial part 2 (G1 point)
 * @param cmT3            commitment to quotient polynomial part 3 (G1 point)
 * @param evalA           evaluation of a(X) at zeta
 * @param evalB           evaluation of b(X) at zeta
 * @param evalC           evaluation of c(X) at zeta
 * @param evalS1          evaluation of S_sigma1(X) at zeta
 * @param evalS2          evaluation of S_sigma2(X) at zeta
 * @param evalZOmega      evaluation of z(X) at zeta*omega
 * @param wZeta           opening proof at zeta (G1 point)
 * @param wZetaOmega      opening proof at zeta*omega (G1 point)
 */
public record PlonkProof(
        List<BigInteger> cmA,
        List<BigInteger> cmB,
        List<BigInteger> cmC,
        List<BigInteger> cmZ,
        List<BigInteger> cmT1,
        List<BigInteger> cmT2,
        List<BigInteger> cmT3,
        BigInteger evalA,
        BigInteger evalB,
        BigInteger evalC,
        BigInteger evalS1,
        BigInteger evalS2,
        BigInteger evalZOmega,
        List<BigInteger> wZeta,
        List<BigInteger> wZetaOmega
) {
    public PlonkProof {
        Objects.requireNonNull(cmA);
        Objects.requireNonNull(cmB);
        Objects.requireNonNull(cmC);
        Objects.requireNonNull(cmZ);
        Objects.requireNonNull(cmT1);
        Objects.requireNonNull(cmT2);
        Objects.requireNonNull(cmT3);
        Objects.requireNonNull(evalA);
        Objects.requireNonNull(evalB);
        Objects.requireNonNull(evalC);
        Objects.requireNonNull(evalS1);
        Objects.requireNonNull(evalS2);
        Objects.requireNonNull(evalZOmega);
        Objects.requireNonNull(wZeta);
        Objects.requireNonNull(wZetaOmega);
        cmA = List.copyOf(cmA);
        cmB = List.copyOf(cmB);
        cmC = List.copyOf(cmC);
        cmZ = List.copyOf(cmZ);
        cmT1 = List.copyOf(cmT1);
        cmT2 = List.copyOf(cmT2);
        cmT3 = List.copyOf(cmT3);
        wZeta = List.copyOf(wZeta);
        wZetaOmega = List.copyOf(wZetaOmega);
    }
}
