package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

/**
 * BN254 quadratic extension field element (Fp2 = Fp[u] / (u^2 + 1)).
 *
 * <p>An element a + b*u where a, b are in Fp. The non-residue is -1 (i.e., u^2 = -1).</p>
 *
 * @param c0 the "real" part (a)
 * @param c1 the "imaginary" part (b)
 */
public record Fp2(Fp c0, Fp c1) {

    public static final Fp2 ZERO = new Fp2(Fp.ZERO, Fp.ZERO);
    public static final Fp2 ONE = new Fp2(Fp.ONE, Fp.ZERO);

    public static Fp2 of(Fp c0, Fp c1) {
        return new Fp2(c0, c1);
    }

    // (a + bu) + (c + du) = (a+c) + (b+d)u
    public Fp2 add(Fp2 other) {
        return new Fp2(c0.add(other.c0), c1.add(other.c1));
    }

    // (a + bu) - (c + du) = (a-c) + (b-d)u
    public Fp2 sub(Fp2 other) {
        return new Fp2(c0.sub(other.c0), c1.sub(other.c1));
    }

    // (a + bu)(c + du) = (ac - bd) + (ad + bc)u  [since u^2 = -1]
    public Fp2 mul(Fp2 other) {
        var ac = c0.mul(other.c0);
        var bd = c1.mul(other.c1);
        // Real: ac - bd
        var real = ac.sub(bd);
        // Imaginary: (a+b)(c+d) - ac - bd = ad + bc
        var imag = c0.add(c1).mul(other.c0.add(other.c1)).sub(ac).sub(bd);
        return new Fp2(real, imag);
    }

    // (a + bu)^2 = (a^2 - b^2) + 2ab*u
    public Fp2 square() {
        var a2 = c0.mul(c0);
        var b2 = c1.mul(c1);
        var ab2 = c0.mul(c1).add(c0.mul(c1));
        return new Fp2(a2.sub(b2), ab2);
    }

    public Fp2 neg() {
        return new Fp2(c0.neg(), c1.neg());
    }

    // conjugate: a + bu -> a - bu
    public Fp2 conjugate() {
        return new Fp2(c0, c1.neg());
    }

    // Norm: (a + bu)(a - bu) = a^2 + b^2  [since u^2 = -1]
    public Fp norm() {
        return c0.square().add(c1.square());
    }

    // Inverse: (a + bu)^{-1} = (a - bu) / (a^2 + b^2)
    public Fp2 inv() {
        var n = norm().inv();
        return new Fp2(c0.mul(n), c1.neg().mul(n));
    }

    // Scalar multiplication by Fp element
    public Fp2 mulScalar(Fp s) {
        return new Fp2(c0.mul(s), c1.mul(s));
    }

    /**
     * Multiply by the non-residue xi = 9 + u used for Fp6 tower construction.
     * (a + bu)(9 + u) = (9a - b) + (a + 9b)u
     */
    public Fp2 mulByNonResidue() {
        var nine = Fp.of(9);
        return new Fp2(
                c0.mul(nine).sub(c1),
                c1.mul(nine).add(c0)
        );
    }

    public boolean isZero() {
        return c0.isZero() && c1.isZero();
    }

    @Override
    public String toString() {
        return "(" + c0 + " + " + c1 + "*u)";
    }
}
