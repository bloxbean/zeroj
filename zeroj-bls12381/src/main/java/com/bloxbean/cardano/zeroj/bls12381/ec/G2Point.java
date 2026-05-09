package com.bloxbean.cardano.zeroj.bls12381.ec;

import com.bloxbean.cardano.zeroj.bls12381.field.*;

import java.math.BigInteger;

/**
 * BLS12-381 G2 point in affine coordinates on the twisted curve y^2 = x^3 + 4(1+u) over Fp2.
 */
public record G2Point(Fp2 x, Fp2 y) {

    public static final G2Point INFINITY = new G2Point(null, null);
    private static final Fp2 B_TWIST = Fp2.of(Fp.of(4), Fp.of(4));

    public G2Point {
        if ((x == null) != (y == null)) {
            throw new IllegalArgumentException("G2 infinity must have both coordinates null");
        }
    }

    public boolean isInfinity() { return x == null; }

    public boolean isOnCurve() {
        if (isInfinity()) return true;
        return y.square().equals(x.square().mul(x).add(B_TWIST));
    }

    public boolean isInSubgroup() {
        return isInfinity() || scalarMul(G1Point.R).isInfinity();
    }

    public boolean isValid() {
        return isOnCurve() && isInSubgroup();
    }

    /** Create from snarkjs projective [[x_c0,x_c1],[y_c0,y_c1],[z_c0,z_c1]]. */
    public static G2Point fromProjective(BigInteger xc0, BigInteger xc1,
                                          BigInteger yc0, BigInteger yc1,
                                          BigInteger zc0, BigInteger zc1) {
        var z = Fp2.of(Fp.of(zc0), Fp.of(zc1));
        if (z.isZero()) return INFINITY;
        if (z.c0().equals(Fp.ONE) && z.c1().isZero()) {
            return new G2Point(Fp2.of(Fp.of(xc0), Fp.of(xc1)), Fp2.of(Fp.of(yc0), Fp.of(yc1)));
        }
        var zInv = z.inv();
        return new G2Point(
                Fp2.of(Fp.of(xc0), Fp.of(xc1)).mul(zInv),
                Fp2.of(Fp.of(yc0), Fp.of(yc1)).mul(zInv));
    }

    public G2Point negate() {
        return isInfinity() ? this : new G2Point(x, y.neg());
    }

    public G2Point add(G2Point o) {
        if (this.isInfinity()) return o;
        if (o.isInfinity()) return this;
        if (this.x.equals(o.x)) {
            return this.y.equals(o.y) ? this.doublePoint() : INFINITY;
        }
        var lambda = o.y.sub(this.y).mul(o.x.sub(this.x).inv());
        var x3 = lambda.square().sub(this.x).sub(o.x);
        var y3 = lambda.mul(this.x.sub(x3)).sub(this.y);
        return new G2Point(x3, y3);
    }

    public G2Point doublePoint() {
        if (isInfinity() || y.isZero()) return INFINITY;
        var three = Fp2.of(Fp.of(3), Fp.ZERO);
        var lambda = x.square().mul(three).mul(y.add(y).inv());
        var x3 = lambda.square().sub(x).sub(x);
        var y3 = lambda.mul(x.sub(x3)).sub(y);
        return new G2Point(x3, y3);
    }

    public G2Point scalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().scalarMul(scalar.negate());
        var result = INFINITY;
        var base = this;
        var s = scalar;
        while (s.signum() > 0) {
            if (s.testBit(0)) result = result.add(base);
            base = base.doublePoint();
            s = s.shiftRight(1);
        }
        return result;
    }

    /**
     * Fixed-schedule scalar multiplication for secret-scalar callers.
     */
    public G2Point ctScalarMul(BigInteger scalar) {
        if (scalar.signum() == 0 || isInfinity()) return INFINITY;
        if (scalar.signum() < 0) return negate().ctScalarMul(scalar.negate());
        var affine = JacobianG2BLS381.fromAffine(
                        MontFp2_381.of(x.c0().value(), x.c1().value()),
                        MontFp2_381.of(y.c0().value(), y.c1().value()))
                .ctScalarMul(scalar)
                .toAffine();
        if (affine.isInfinity()) {
            return INFINITY;
        }
        return new G2Point(
                Fp2.of(Fp.of(affine.x().reBigInt()), Fp.of(affine.x().imBigInt())),
                Fp2.of(Fp.of(affine.y().reBigInt()), Fp.of(affine.y().imBigInt())));
    }
}
