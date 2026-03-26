package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import java.math.BigInteger;

/**
 * BN254 dodecic extension field element (Fp12 = Fp6[w] / (w^2 - v)).
 *
 * <p>An element c0 + c1*w where c0, c1 are in Fp6.
 * w^2 = v (the generator of the Fp6 extension).</p>
 *
 * @param c0 coefficient of 1
 * @param c1 coefficient of w
 */
public record Fp12(Fp6 c0, Fp6 c1) {

    public static final Fp12 ZERO = new Fp12(Fp6.ZERO, Fp6.ZERO);
    public static final Fp12 ONE = new Fp12(Fp6.ONE, Fp6.ZERO);

    public Fp12 add(Fp12 other) {
        return new Fp12(c0.add(other.c0), c1.add(other.c1));
    }

    public Fp12 sub(Fp12 other) {
        return new Fp12(c0.sub(other.c0), c1.sub(other.c1));
    }

    public Fp12 neg() {
        return new Fp12(c0.neg(), c1.neg());
    }

    /**
     * Multiplication in Fp12.
     * (a0 + a1*w)(b0 + b1*w) = (a0*b0 + a1*b1*v) + (a0*b1 + a1*b0)*w
     * where v is "mulByV" — multiply Fp6 by v, which shifts coefficients and multiplies by xi.
     */
    public Fp12 mul(Fp12 other) {
        var a0b0 = c0.mul(other.c0);
        var a1b1 = c1.mul(other.c1);

        // c0 = a0*b0 + a1*b1*v (mulByV shifts and multiplies c2 by xi)
        var r0 = a0b0.add(mulByV(a1b1));
        // c1 = (a0+a1)(b0+b1) - a0*b0 - a1*b1
        var r1 = c0.add(c1).mul(other.c0.add(other.c1)).sub(a0b0).sub(a1b1);

        return new Fp12(r0, r1);
    }

    public Fp12 square() {
        var ab = c0.mul(c1);

        // c0 = (a + b)(a + v*b) - ab - v*ab
        var r0 = c0.add(c1).mul(c0.add(mulByV(c1))).sub(ab).sub(mulByV(ab));
        // c1 = 2*ab
        var r1 = ab.add(ab);

        return new Fp12(r0, r1);
    }

    public Fp12 inv() {
        // (a + bw)^{-1} = (a - bw) / (a^2 - b^2 * v)
        var a2 = c0.mul(c0);
        var b2v = mulByV(c1.mul(c1));
        var t = a2.sub(b2v).inv();
        return new Fp12(c0.mul(t), c1.neg().mul(t));
    }

    /**
     * Conjugation in Fp12: (a + bw) -> (a - bw).
     * This is the unitary inverse for elements on the cyclotomic subgroup.
     */
    public Fp12 conjugate() {
        return new Fp12(c0, c1.neg());
    }

    /**
     * Frobenius endomorphism (raise to the p-th power).
     * Used in final exponentiation.
     */
    public Fp12 frobeniusMap(int power) {
        // For the basic implementation, we use the exponentiation approach
        // For Groth16 verification, we primarily need the final exponentiation
        // which uses a specific decomposition. This is a placeholder.
        if (power == 0) return this;
        // Full Frobenius implementation requires precomputed constants
        // For now, we use the conjugation shortcut for power=6 (which gives cyclotomic inverse)
        if (power == 6) return conjugate();
        throw new UnsupportedOperationException("Frobenius map power " + power + " not yet implemented");
    }

    /**
     * Exponentiation. Used in final exponentiation.
     */
    public Fp12 pow(BigInteger exp) {
        if (exp.signum() == 0) return ONE;
        if (exp.signum() < 0) return inv().pow(exp.negate());

        var result = ONE;
        var base = this;
        var e = exp;

        while (e.signum() > 0) {
            if (e.testBit(0)) {
                result = result.mul(base);
            }
            base = base.square();
            e = e.shiftRight(1);
        }
        return result;
    }

    public boolean isOne() {
        return c0.c0().c0().equals(Fp.ONE) && c0.c0().c1().isZero()
                && c0.c1().isZero() && c0.c2().isZero()
                && c1.isZero();
    }

    /**
     * Multiply an Fp6 element by v (the Fp6 generator).
     * v * (a, b, c) = (c*xi, a, b) where xi is the Fp2 non-residue.
     */
    private static Fp6 mulByV(Fp6 f) {
        return new Fp6(f.c2().mulByNonResidue(), f.c0(), f.c1());
    }
}
