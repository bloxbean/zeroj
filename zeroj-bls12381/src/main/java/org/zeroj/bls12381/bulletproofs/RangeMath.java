package org.zeroj.bls12381.bulletproofs;

import java.math.BigInteger;

/**
 * Scalar arithmetic mod {@code q} for the range proof (spec §7.2, §8.3). Every result is in
 * {@code [0, q)}. {@link BigInteger} is variable-time; the prover's use on secrets is the documented
 * ADR-0038 offline/isolated restriction (spec §7.4).
 */
final class RangeMath {

    static final BigInteger Q = PointCodec.Q;

    private RangeMath() {
    }

    static BigInteger add(BigInteger a, BigInteger b) {
        return a.add(b).mod(Q);
    }

    static BigInteger sub(BigInteger a, BigInteger b) {
        return a.subtract(b).mod(Q);
    }

    static BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(Q);
    }

    static BigInteger neg(BigInteger a) {
        return a.negate().mod(Q);
    }

    /** {@code a⁻¹ mod q}, for {@code a ≠ 0}. */
    static BigInteger inv(BigInteger a) {
        if (a.signum() == 0) {
            throw new IllegalStateException("zero has no inverse");
        }
        return a.modInverse(Q);
    }

    /** {@code (1, c, c², …, c^{t−1})}. */
    static BigInteger[] powers(BigInteger c, int t) {
        BigInteger[] out = new BigInteger[t];
        BigInteger acc = BigInteger.ONE;
        for (int i = 0; i < t; i++) {
            out[i] = acc;
            acc = mul(acc, c);
        }
        return out;
    }

    /** {@code ⟨a, b⟩ mod q} over {@code a[aFrom …]} and {@code b[bFrom …]}, {@code t} terms. */
    static BigInteger inner(BigInteger[] a, int aFrom, BigInteger[] b, int bFrom, int t) {
        BigInteger acc = BigInteger.ZERO;
        for (int i = 0; i < t; i++) {
            acc = acc.add(a[aFrom + i].multiply(b[bFrom + i]));
        }
        return acc.mod(Q);
    }

    /** {@code ⟨a, b⟩ mod q} over equal-length vectors. */
    static BigInteger inner(BigInteger[] a, BigInteger[] b) {
        return inner(a, 0, b, 0, a.length);
    }

    /** {@code Σ_{i<t} c^i mod q} = {@code ⟨1ⁿ, cⁿ⟩}. */
    static BigInteger sumOfPowers(BigInteger c, int t) {
        BigInteger acc = BigInteger.ZERO;
        BigInteger p = BigInteger.ONE;
        for (int i = 0; i < t; i++) {
            acc = acc.add(p);
            p = mul(p, c);
        }
        return acc.mod(Q);
    }

    /**
     * {@code δ(y, z) = (z − z²)·⟨1ⁿ, yⁿ⟩ − z³·⟨1ⁿ, 2ⁿ⟩} (spec §8.3), with {@code ⟨1ⁿ, 2ⁿ⟩ = 2ⁿ − 1}.
     */
    static BigInteger delta(BigInteger y, BigInteger z, int n) {
        BigInteger z2 = mul(z, z);
        BigInteger z3 = mul(z2, z);
        BigInteger twoN = BigInteger.ONE.shiftLeft(n).subtract(BigInteger.ONE).mod(Q);
        return sub(mul(sub(z, z2), sumOfPowers(y, n)), mul(z3, twoN));
    }

    /**
     * The challenge products {@code s_i = Π_{j=1…k} x_j^{e(i, j)}}, {@code e(i, j) = +1} if bit
     * {@code k − j} of {@code i} is 1, else {@code −1} (spec §8.3: most significant bit first).
     *
     * @param x    {@code x_1 … x_k}, all non-zero
     * @param xInv their inverses
     */
    static BigInteger[] challengeProducts(BigInteger[] x, BigInteger[] xInv, int n) {
        int k = x.length;
        BigInteger[] s = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            BigInteger acc = BigInteger.ONE;
            for (int j = 1; j <= k; j++) {
                boolean bit = ((i >>> (k - j)) & 1) == 1;
                acc = acc.multiply(bit ? x[j - 1] : xInv[j - 1]).mod(Q);
            }
            s[i] = acc;
        }
        return s;
    }
}
