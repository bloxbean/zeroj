package com.bloxbean.cardano.zeroj.codec;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Parsed representation of a snarkjs PlonK verification_key.json file.
 *
 * @param protocol    proof system identifier (e.g., "plonk")
 * @param curve       curve identifier (e.g., "bn128", "bls12381")
 * @param nPublic     number of public inputs
 * @param power       power of 2 for domain size (domain_size = 2^power)
 * @param k1          coset generator k1
 * @param k2          coset generator k2
 * @param Qm          selector commitment q_M (G1 point)
 * @param Ql          selector commitment q_L
 * @param Qr          selector commitment q_R
 * @param Qo          selector commitment q_O
 * @param Qc          selector commitment q_C
 * @param S1          permutation commitment sigma_1
 * @param S2          permutation commitment sigma_2
 * @param S3          permutation commitment sigma_3
 * @param X_2         SRS G2 point [tau]_2 (G2 point for KZG)
 * @param w           primitive root of unity for the evaluation domain
 */
public record SnarkjsPlonkVerificationKey(
        String protocol,
        String curve,
        int nPublic,
        int power,
        BigInteger k1,
        BigInteger k2,
        List<BigInteger> Qm,
        List<BigInteger> Ql,
        List<BigInteger> Qr,
        List<BigInteger> Qo,
        List<BigInteger> Qc,
        List<BigInteger> S1,
        List<BigInteger> S2,
        List<BigInteger> S3,
        List<List<BigInteger>> X_2,
        BigInteger w
) {
    public SnarkjsPlonkVerificationKey {
        Objects.requireNonNull(protocol);
        Objects.requireNonNull(curve);
        Objects.requireNonNull(k1);
        Objects.requireNonNull(k2);
        Objects.requireNonNull(Qm);
        Objects.requireNonNull(Ql);
        Objects.requireNonNull(Qr);
        Objects.requireNonNull(Qo);
        Objects.requireNonNull(Qc);
        Objects.requireNonNull(S1);
        Objects.requireNonNull(S2);
        Objects.requireNonNull(S3);
        Objects.requireNonNull(X_2);
        Objects.requireNonNull(w);
        Qm = List.copyOf(Qm);
        Ql = List.copyOf(Ql);
        Qr = List.copyOf(Qr);
        Qo = List.copyOf(Qo);
        Qc = List.copyOf(Qc);
        S1 = List.copyOf(S1);
        S2 = List.copyOf(S2);
        S3 = List.copyOf(S3);
        X_2 = X_2.stream().map(List::copyOf).toList();
    }

    /**
     * Domain size = 2^power.
     */
    public int domainSize() {
        return 1 << power;
    }
}
