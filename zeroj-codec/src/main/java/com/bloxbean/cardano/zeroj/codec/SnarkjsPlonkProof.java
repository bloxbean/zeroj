package com.bloxbean.cardano.zeroj.codec;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Parsed representation of a snarkjs PlonK proof.json file.
 *
 * <p>Contains commitments (G1 points as [x, y, z] projective coordinates)
 * and scalar evaluations from the PlonK proof.</p>
 *
 * @param A         commitment to left wire polynomial (G1 point [x, y, z])
 * @param B         commitment to right wire polynomial
 * @param C         commitment to output wire polynomial
 * @param Z         commitment to grand product polynomial
 * @param T1        quotient polynomial part 1
 * @param T2        quotient polynomial part 2
 * @param T3        quotient polynomial part 3
 * @param evalA     evaluation of a(X) at zeta
 * @param evalB     evaluation of b(X) at zeta
 * @param evalC     evaluation of c(X) at zeta
 * @param evalS1    evaluation of S_sigma1(X) at zeta
 * @param evalS2    evaluation of S_sigma2(X) at zeta
 * @param evalZw    evaluation of z(X) at zeta*omega
 * @param Wxi       opening proof at zeta (G1 point)
 * @param Wxiw      opening proof at zeta*omega (G1 point)
 * @param protocol  proof system identifier (e.g., "plonk")
 * @param curve     curve identifier (e.g., "bn128", "bls12381")
 */
public record SnarkjsPlonkProof(
        List<BigInteger> A,
        List<BigInteger> B,
        List<BigInteger> C,
        List<BigInteger> Z,
        List<BigInteger> T1,
        List<BigInteger> T2,
        List<BigInteger> T3,
        BigInteger evalA,
        BigInteger evalB,
        BigInteger evalC,
        BigInteger evalS1,
        BigInteger evalS2,
        BigInteger evalZw,
        List<BigInteger> Wxi,
        List<BigInteger> Wxiw,
        String protocol,
        String curve
) {
    public SnarkjsPlonkProof {
        Objects.requireNonNull(A);
        Objects.requireNonNull(B);
        Objects.requireNonNull(C);
        Objects.requireNonNull(Z);
        Objects.requireNonNull(T1);
        Objects.requireNonNull(T2);
        Objects.requireNonNull(T3);
        Objects.requireNonNull(evalA);
        Objects.requireNonNull(evalB);
        Objects.requireNonNull(evalC);
        Objects.requireNonNull(evalS1);
        Objects.requireNonNull(evalS2);
        Objects.requireNonNull(evalZw);
        Objects.requireNonNull(Wxi);
        Objects.requireNonNull(Wxiw);
        Objects.requireNonNull(protocol);
        Objects.requireNonNull(curve);
        A = List.copyOf(A);
        B = List.copyOf(B);
        C = List.copyOf(C);
        Z = List.copyOf(Z);
        T1 = List.copyOf(T1);
        T2 = List.copyOf(T2);
        T3 = List.copyOf(T3);
        Wxi = List.copyOf(Wxi);
        Wxiw = List.copyOf(Wxiw);
    }
}
