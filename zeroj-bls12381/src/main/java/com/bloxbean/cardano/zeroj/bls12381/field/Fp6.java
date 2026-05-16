package com.bloxbean.cardano.zeroj.bls12381.field;

/**
 * BLS12-381 sextic extension field element (Fp6 = Fp2[v] / (v^3 - xi)).
 *
 * <p>An element c0 + c1*v + c2*v^2 where c0, c1, c2 are in Fp2.
 * xi = 1 + u (the non-residue in Fp2 for BLS12-381).</p>
 */
public record Fp6(Fp2 c0, Fp2 c1, Fp2 c2) {

    public static final Fp6 ZERO = new Fp6(Fp2.ZERO, Fp2.ZERO, Fp2.ZERO);
    public static final Fp6 ONE = new Fp6(Fp2.ONE, Fp2.ZERO, Fp2.ZERO);

    public Fp6 add(Fp6 o) { return new Fp6(c0.add(o.c0), c1.add(o.c1), c2.add(o.c2)); }
    public Fp6 sub(Fp6 o) { return new Fp6(c0.sub(o.c0), c1.sub(o.c1), c2.sub(o.c2)); }
    public Fp6 neg() { return new Fp6(c0.neg(), c1.neg(), c2.neg()); }

    public Fp6 mul(Fp6 o) {
        var t0 = c0.mul(o.c0);
        var t1 = c1.mul(o.c1);
        var t2 = c2.mul(o.c2);

        var r0 = t0.add(c1.add(c2).mul(o.c1.add(o.c2)).sub(t1).sub(t2).mulByNonResidue());
        var r1 = c0.add(c1).mul(o.c0.add(o.c1)).sub(t0).sub(t1).add(t2.mulByNonResidue());
        var r2 = c0.add(c2).mul(o.c0.add(o.c2)).sub(t0).sub(t2).add(t1);

        return new Fp6(r0, r1, r2);
    }

    public Fp6 square() {
        var s0 = c0.square();
        var ab = c0.mul(c1);
        var s1 = ab.add(ab);
        var s2 = c0.sub(c1).add(c2).square();
        var bc = c1.mul(c2);
        var s3 = bc.add(bc);
        var s4 = c2.square();

        return new Fp6(
                s0.add(s3.mulByNonResidue()),
                s1.add(s4.mulByNonResidue()),
                s1.add(s2).add(s3).sub(s0).sub(s4));
    }

    public Fp6 inv() {
        var c0s = c0.square();
        var c1s = c1.square();
        var c2s = c2.square();

        var t0 = c0s.sub(c1.mul(c2).mulByNonResidue());
        var t1 = c2s.mulByNonResidue().sub(c0.mul(c1));
        var t2 = c1s.sub(c0.mul(c2));

        var inv = c0.mul(t0).add(c2.mul(t1).mulByNonResidue()).add(c1.mul(t2).mulByNonResidue()).inv();
        return new Fp6(t0.mul(inv), t1.mul(inv), t2.mul(inv));
    }

    public boolean isZero() { return c0.isZero() && c1.isZero() && c2.isZero(); }
}
