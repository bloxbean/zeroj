package com.bloxbean.cardano.zeroj.bls12381.ec;

import com.bloxbean.cardano.zeroj.bls12381.field.*;

import java.math.BigInteger;

/**
 * BLS12-381 G1 point in affine coordinates on the curve y^2 = x^3 + 4 over Fp.
 */
public record G1Point(Fp x, Fp y) {

    public static final G1Point INFINITY = new G1Point(null, null);
    private static final Fp B = Fp.of(4);

    /** Scalar field order r. */
    public static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    public G1Point {
        if ((x == null) != (y == null)) {
            throw new IllegalArgumentException("G1 infinity must have both coordinates null");
        }
    }

    public boolean isInfinity() { return x == null; }

    public boolean isOnCurve() {
        if (isInfinity()) return true;
        return y.square().equals(x.square().mul(x).add(B));
    }

    public boolean isInSubgroup() {
        return isInfinity() || scalarMul(R).isInfinity();
    }

    public boolean isValid() {
        return isOnCurve() && isInSubgroup();
    }

    /** Create from snarkjs projective [x, y, z] coordinates. */
    public static G1Point fromProjective(BigInteger px, BigInteger py, BigInteger pz) {
        if (pz.signum() == 0) return INFINITY;
        if (pz.equals(BigInteger.ONE)) return new G1Point(Fp.of(px), Fp.of(py));
        var zInv = Fp.of(pz).inv();
        return new G1Point(Fp.of(px).mul(zInv), Fp.of(py).mul(zInv));
    }

    public G1Point negate() {
        return isInfinity() ? this : new G1Point(x, y.neg());
    }

    public G1Point add(G1Point o) {
        if (this.isInfinity()) return o;
        if (o.isInfinity()) return this;
        if (this.x.equals(o.x)) {
            return this.y.equals(o.y) ? this.doublePoint() : INFINITY;
        }
        var lambda = o.y.sub(this.y).mul(o.x.sub(this.x).inv());
        var x3 = lambda.square().sub(this.x).sub(o.x);
        var y3 = lambda.mul(this.x.sub(x3)).sub(this.y);
        return new G1Point(x3, y3);
    }

    public G1Point doublePoint() {
        if (isInfinity() || y.isZero()) return INFINITY;
        // lambda = 3*x^2 / (2*y)  [a=0 for BLS12-381]
        var lambda = x.square().mul(Fp.of(3)).mul(y.add(y).inv());
        var x3 = lambda.square().sub(x).sub(x);
        var y3 = lambda.mul(x.sub(x3)).sub(y);
        return new G1Point(x3, y3);
    }

    public G1Point scalarMul(BigInteger scalar) {
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
     *
     * <p>This delegates to the pure-Java Jacobian ladder. It has a uniform operation
     * schedule, but it is not a JVM constant-time guarantee.</p>
     */
    public G1Point ctScalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().ctScalarMul(scalar.negate());
        if (scalar.bitLength() > 256) {
            throw new IllegalArgumentException("ctScalarMul scalar must fit in 256 bits");
        }
        if (isInfinity()) return INFINITY;
        var affine = JacobianG1BLS381.fromAffine(x.value(), y.value())
                .ctScalarMul(scalar)
                .toAffine();
        if (affine.isInfinity()) {
            return INFINITY;
        }
        return new G1Point(Fp.of(affine.xBigInt()), Fp.of(affine.yBigInt()));
    }
}
