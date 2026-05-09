package com.bloxbean.cardano.zeroj.bls12381.field;

import java.math.BigInteger;

/**
 * BLS12-381 dodecic extension field element (Fp12 = Fp6[w] / (w^2 - v)).
 *
 * <p>An element c0 + c1*w where c0, c1 are in Fp6.
 * w^2 = v (the generator of the Fp6 extension).</p>
 */
public record Fp12(Fp6 c0, Fp6 c1) {

    public static final Fp12 ZERO = new Fp12(Fp6.ZERO, Fp6.ZERO);
    public static final Fp12 ONE = new Fp12(Fp6.ONE, Fp6.ZERO);

    public Fp12 add(Fp12 o) { return new Fp12(c0.add(o.c0), c1.add(o.c1)); }
    public Fp12 sub(Fp12 o) { return new Fp12(c0.sub(o.c0), c1.sub(o.c1)); }
    public Fp12 neg() { return new Fp12(c0.neg(), c1.neg()); }

    public Fp12 mul(Fp12 o) {
        var a0b0 = c0.mul(o.c0);
        var a1b1 = c1.mul(o.c1);
        return new Fp12(
                a0b0.add(mulByV(a1b1)),
                c0.add(c1).mul(o.c0.add(o.c1)).sub(a0b0).sub(a1b1));
    }

    public Fp12 square() {
        var ab = c0.mul(c1);
        return new Fp12(
                c0.add(c1).mul(c0.add(mulByV(c1))).sub(ab).sub(mulByV(ab)),
                ab.add(ab));
    }

    public Fp12 inv() {
        var a2 = c0.mul(c0);
        var b2v = mulByV(c1.mul(c1));
        var t = a2.sub(b2v).inv();
        return new Fp12(c0.mul(t), c1.neg().mul(t));
    }

    /** Conjugation: (a + bw) -> (a - bw). Unitary inverse for cyclotomic elements. */
    public Fp12 conjugate() { return new Fp12(c0, c1.neg()); }

    /** Exponentiation via square-and-multiply. */
    public Fp12 pow(BigInteger exp) {
        if (exp.signum() == 0) return ONE;
        if (exp.signum() < 0) return inv().pow(exp.negate());
        var result = ONE;
        var base = this;
        var e = exp;
        while (e.signum() > 0) {
            if (e.testBit(0)) result = result.mul(base);
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

    /** Multiply Fp6 by v: v*(a,b,c) = (c*xi, a, b) */
    private static Fp6 mulByV(Fp6 f) {
        return new Fp6(f.c2().mulByNonResidue(), f.c0(), f.c1());
    }
}
