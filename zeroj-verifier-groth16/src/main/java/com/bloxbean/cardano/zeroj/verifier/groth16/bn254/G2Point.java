package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import java.math.BigInteger;

/**
 * BN254 G2 point in affine coordinates (x, y) on the twisted curve y^2 = x^3 + b' over Fp2.
 *
 * <p>b' = 3 / (9 + u) = 3 * (9 + u)^{-1}.</p>
 */
public record G2Point(Fp2 x, Fp2 y) {

    /** Point at infinity. */
    public static final G2Point INFINITY = new G2Point(null, null);

    public boolean isInfinity() {
        return x == null;
    }

    /**
     * Create a G2 point from snarkjs projective coordinates.
     * snarkjs encodes G2 as [[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]].
     */
    public static G2Point fromProjective(BigInteger xc0, BigInteger xc1,
                                          BigInteger yc0, BigInteger yc1,
                                          BigInteger zc0, BigInteger zc1) {
        var z = Fp2.of(Fp.of(zc0), Fp.of(zc1));
        if (z.isZero()) return INFINITY;
        if (z.c0().equals(Fp.ONE) && z.c1().isZero()) {
            return new G2Point(
                    Fp2.of(Fp.of(xc0), Fp.of(xc1)),
                    Fp2.of(Fp.of(yc0), Fp.of(yc1)));
        }
        var zInv = z.inv();
        return new G2Point(
                Fp2.of(Fp.of(xc0), Fp.of(xc1)).mul(zInv),
                Fp2.of(Fp.of(yc0), Fp.of(yc1)).mul(zInv));
    }

    /** Negate: (x, y) -> (x, -y). */
    public G2Point negate() {
        if (isInfinity()) return this;
        return new G2Point(x, y.neg());
    }

    /** Point addition. */
    public G2Point add(G2Point other) {
        if (this.isInfinity()) return other;
        if (other.isInfinity()) return this;

        if (this.x.equals(other.x)) {
            if (this.y.equals(other.y)) {
                return this.doublePoint();
            }
            return INFINITY;
        }

        var dy = other.y.sub(this.y);
        var dx = other.x.sub(this.x);
        var lambda = dy.mul(dx.inv());

        var x3 = lambda.square().sub(this.x).sub(other.x);
        var y3 = lambda.mul(this.x.sub(x3)).sub(this.y);

        return new G2Point(x3, y3);
    }

    /** Point doubling. */
    public G2Point doublePoint() {
        if (isInfinity()) return this;
        if (y.isZero()) return INFINITY;

        var num = x.square().add(x.square()).add(x.square()); // 3*x^2
        var den = y.add(y);
        var lambda = num.mul(den.inv());

        var x3 = lambda.square().sub(x).sub(x);
        var y3 = lambda.mul(x.sub(x3)).sub(y);

        return new G2Point(x3, y3);
    }

    /** Scalar multiplication. */
    public G2Point scalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().scalarMul(scalar.negate());

        var result = INFINITY;
        var base = this;
        var s = scalar;

        while (s.signum() > 0) {
            if (s.testBit(0)) {
                result = result.add(base);
            }
            base = base.doublePoint();
            s = s.shiftRight(1);
        }
        return result;
    }
}
