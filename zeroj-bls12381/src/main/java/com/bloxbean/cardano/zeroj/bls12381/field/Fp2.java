package com.bloxbean.cardano.zeroj.bls12381.field;

import java.math.BigInteger;
import java.util.Optional;

/**
 * BLS12-381 quadratic extension field element (Fp2 = Fp[u] / (u^2 + 1)).
 *
 * <p>An element a + b*u where a, b are in Fp. u^2 = -1.</p>
 */
public record Fp2(Fp c0, Fp c1) {

    private static final BigInteger P_MINUS_THREE_OVER_FOUR = Fp.P.subtract(BigInteger.valueOf(3)).shiftRight(2);
    private static final BigInteger P_MINUS_ONE_OVER_TWO = Fp.P.subtract(BigInteger.ONE).shiftRight(1);

    public static final Fp2 ZERO = new Fp2(Fp.ZERO, Fp.ZERO);
    public static final Fp2 ONE = new Fp2(Fp.ONE, Fp.ZERO);

    public static Fp2 of(Fp c0, Fp c1) { return new Fp2(c0, c1); }

    public Fp2 add(Fp2 o) { return new Fp2(c0.add(o.c0), c1.add(o.c1)); }
    public Fp2 sub(Fp2 o) { return new Fp2(c0.sub(o.c0), c1.sub(o.c1)); }

    // (a+bu)(c+du) = (ac-bd) + (ad+bc)u
    public Fp2 mul(Fp2 o) {
        var ac = c0.mul(o.c0);
        var bd = c1.mul(o.c1);
        return new Fp2(ac.sub(bd), c0.add(c1).mul(o.c0.add(o.c1)).sub(ac).sub(bd));
    }

    public Fp2 square() {
        var a2 = c0.mul(c0);
        var b2 = c1.mul(c1);
        return new Fp2(a2.sub(b2), c0.mul(c1).add(c0.mul(c1)));
    }

    public Fp2 neg() { return new Fp2(c0.neg(), c1.neg()); }
    public Fp2 conjugate() { return new Fp2(c0, c1.neg()); }
    public Fp norm() { return c0.square().add(c1.square()); }
    public Fp2 inv() { var n = norm().inv(); return new Fp2(c0.mul(n), c1.neg().mul(n)); }
    public Fp2 div(Fp2 o) { return mul(o.inv()); }
    public Fp2 mulScalar(Fp s) { return new Fp2(c0.mul(s), c1.mul(s)); }
    public Fp2 pow(BigInteger exp) {
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
    public Optional<Fp2> sqrt() {
        if (isZero()) return Optional.of(ZERO);

        var a1 = pow(P_MINUS_THREE_OVER_FOUR);
        var alpha = a1.square().mul(this);
        var x0 = a1.mul(this);
        Fp2 root;
        if (alpha.equals(ONE.neg())) {
            root = new Fp2(x0.c1.neg(), x0.c0);
        } else {
            root = alpha.add(ONE).pow(P_MINUS_ONE_OVER_TWO).mul(x0);
        }
        return root.square().equals(this) ? Optional.of(root) : Optional.empty();
    }

    /**
     * Multiply by the non-residue xi = 1 + u used for BLS12-381 Fp6 tower.
     * (a + bu)(1 + u) = (a - b) + (a + b)u
     */
    public Fp2 mulByNonResidue() {
        return new Fp2(c0.sub(c1), c0.add(c1));
    }

    public boolean isZero() { return c0.isZero() && c1.isZero(); }
    public boolean sgn0() { return c0.sgn0() || (c0.isZero() && c1.sgn0()); }
    public boolean lexicographicallyLargest() {
        return c1.lexicographicallyLargest() || (c1.isZero() && c0.lexicographicallyLargest());
    }

    @Override public String toString() { return "(" + c0 + " + " + c1 + "*u)"; }
}
