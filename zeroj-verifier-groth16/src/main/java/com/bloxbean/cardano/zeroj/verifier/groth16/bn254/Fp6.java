package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

/**
 * BN254 sextic extension field element (Fp6 = Fp2[v] / (v^3 - xi)).
 *
 * <p>An element c0 + c1*v + c2*v^2 where c0, c1, c2 are in Fp2.
 * The non-residue xi = 9 + u (in Fp2).</p>
 *
 * @param c0 coefficient of 1
 * @param c1 coefficient of v
 * @param c2 coefficient of v^2
 */
public record Fp6(Fp2 c0, Fp2 c1, Fp2 c2) {

    public static final Fp6 ZERO = new Fp6(Fp2.ZERO, Fp2.ZERO, Fp2.ZERO);
    public static final Fp6 ONE = new Fp6(Fp2.ONE, Fp2.ZERO, Fp2.ZERO);

    public Fp6 add(Fp6 other) {
        return new Fp6(c0.add(other.c0), c1.add(other.c1), c2.add(other.c2));
    }

    public Fp6 sub(Fp6 other) {
        return new Fp6(c0.sub(other.c0), c1.sub(other.c1), c2.sub(other.c2));
    }

    public Fp6 neg() {
        return new Fp6(c0.neg(), c1.neg(), c2.neg());
    }

    /**
     * Multiplication in Fp6 using Karatsuba-like method.
     * v^3 = xi (the non-residue in Fp2).
     */
    public Fp6 mul(Fp6 other) {
        var a0 = c0;
        var a1 = c1;
        var a2 = c2;
        var b0 = other.c0;
        var b1 = other.c1;
        var b2 = other.c2;

        var t0 = a0.mul(b0);
        var t1 = a1.mul(b1);
        var t2 = a2.mul(b2);

        // c0 = t0 + xi*((a1+a2)(b1+b2) - t1 - t2)
        var r0 = t0.add(a1.add(a2).mul(b1.add(b2)).sub(t1).sub(t2).mulByNonResidue());

        // c1 = (a0+a1)(b0+b1) - t0 - t1 + xi*t2
        var r1 = a0.add(a1).mul(b0.add(b1)).sub(t0).sub(t1).add(t2.mulByNonResidue());

        // c2 = (a0+a2)(b0+b2) - t0 - t2 + t1
        var r2 = a0.add(a2).mul(b0.add(b2)).sub(t0).sub(t2).add(t1);

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

        // c0 = s0 + xi*s3
        var r0 = s0.add(s3.mulByNonResidue());
        // c1 = s1 + xi*s4
        var r1 = s1.add(s4.mulByNonResidue());
        // c2 = s1 + s2 + s3 - s0 - s4
        var r2 = s1.add(s2).add(s3).sub(s0).sub(s4);

        return new Fp6(r0, r1, r2);
    }

    public Fp6 inv() {
        // Using the formula for cubic extension inverse
        var c0s = c0.square();
        var c1s = c1.square();
        var c2s = c2.square();

        var t0 = c0s.sub(c1.mul(c2).mulByNonResidue());
        var t1 = c2s.mulByNonResidue().sub(c0.mul(c1));
        var t2 = c1s.sub(c0.mul(c2));

        var inv = c0.mul(t0).add(c2.mul(t1).mulByNonResidue()).add(c1.mul(t2).mulByNonResidue()).inv();

        return new Fp6(t0.mul(inv), t1.mul(inv), t2.mul(inv));
    }

    /**
     * Multiply by a "sparse" Fp6 element of the form (c0, c1, 0).
     * Used in line evaluation during pairing.
     */
    public Fp6 mulBy01(Fp2 d0, Fp2 d1) {
        var a = c0.mul(d0);
        var b = c1.mul(d1);

        var r0 = a.add(c2.mul(d1).mulByNonResidue());
        var r1 = c0.add(c1).mul(d0.add(d1)).sub(a).sub(b);
        var r2 = c0.add(c2).mul(d0).sub(a).add(b);

        return new Fp6(r0, r1, r2);
    }

    public boolean isZero() {
        return c0.isZero() && c1.isZero() && c2.isZero();
    }
}
