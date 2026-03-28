package com.bloxbean.cardano.zeroj.verifier.plonk;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Parsed PlonK verification key.
 *
 * <p>Contains the selector commitments, permutation commitments, SRS G2 points,
 * and domain size needed for PlonK verification.</p>
 *
 * @param nPublic          number of public inputs
 * @param domainSize       size of the evaluation domain (power of 2)
 * @param omega            primitive root of unity for the domain
 * @param qL               selector commitment: q_L (G1 point)
 * @param qR               selector commitment: q_R (G1 point)
 * @param qO               selector commitment: q_O (G1 point)
 * @param qM               selector commitment: q_M (G1 point)
 * @param qC               selector commitment: q_C (G1 point)
 * @param s1               permutation commitment: S_sigma1 (G1 point)
 * @param s2               permutation commitment: S_sigma2 (G1 point)
 * @param s3               permutation commitment: S_sigma3 (G1 point)
 * @param x2               SRS G2 point [s]_2 (for KZG verification)
 * @param k1               coset shift factor k1
 * @param k2               coset shift factor k2
 * @param protocol         proof system identifier
 * @param curve            curve identifier
 */
public record PlonkVerificationKey(
        int nPublic,
        int domainSize,
        BigInteger omega,
        List<BigInteger> qL,
        List<BigInteger> qR,
        List<BigInteger> qO,
        List<BigInteger> qM,
        List<BigInteger> qC,
        List<BigInteger> s1,
        List<BigInteger> s2,
        List<BigInteger> s3,
        List<List<BigInteger>> x2,
        BigInteger k1,
        BigInteger k2,
        String protocol,
        String curve
) {
    public PlonkVerificationKey {
        Objects.requireNonNull(omega);
        Objects.requireNonNull(qL);
        Objects.requireNonNull(qR);
        Objects.requireNonNull(qO);
        Objects.requireNonNull(qM);
        Objects.requireNonNull(qC);
        Objects.requireNonNull(s1);
        Objects.requireNonNull(s2);
        Objects.requireNonNull(s3);
        Objects.requireNonNull(x2);
        Objects.requireNonNull(k1);
        Objects.requireNonNull(k2);
        Objects.requireNonNull(protocol);
        Objects.requireNonNull(curve);
        qL = List.copyOf(qL);
        qR = List.copyOf(qR);
        qO = List.copyOf(qO);
        qM = List.copyOf(qM);
        qC = List.copyOf(qC);
        s1 = List.copyOf(s1);
        s2 = List.copyOf(s2);
        s3 = List.copyOf(s3);
        x2 = x2.stream().map(List::copyOf).toList();
    }
}
