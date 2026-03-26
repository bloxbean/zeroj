package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import java.math.BigInteger;

/**
 * BN254 G1 point in affine coordinates (x, y) on the curve y^2 = x^3 + 3 over Fp.
 *
 * <p>The point at infinity is represented by {@link #INFINITY} with null coordinates.</p>
 */
public record G1Point(Fp x, Fp y) {

    /** Point at infinity (identity element). */
    public static final G1Point INFINITY = new G1Point(null, null);

    /** Generator point G1 = (1, 2). */
    public static final G1Point GENERATOR = new G1Point(Fp.ONE, Fp.of(2));

    /** Curve parameter b = 3. */
    private static final Fp B = Fp.of(3);

    /** Scalar field order r. */
    public static final BigInteger R = new BigInteger(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    public boolean isInfinity() {
        return x == null;
    }

    /**
     * Create a G1 point from snarkjs projective coordinates [x, y, z].
     * Converts to affine by dividing by z.
     */
    public static G1Point fromProjective(BigInteger px, BigInteger py, BigInteger pz) {
        if (pz.signum() == 0) return INFINITY;
        if (pz.equals(BigInteger.ONE)) {
            return new G1Point(Fp.of(px), Fp.of(py));
        }
        var zInv = Fp.of(pz).inv();
        return new G1Point(Fp.of(px).mul(zInv), Fp.of(py).mul(zInv));
    }

    /** Negate: (x, y) -> (x, -y). */
    public G1Point negate() {
        if (isInfinity()) return this;
        return new G1Point(x, y.neg());
    }

    /** Point addition using affine coordinates. */
    public G1Point add(G1Point other) {
        if (this.isInfinity()) return other;
        if (other.isInfinity()) return this;

        if (this.x.equals(other.x)) {
            if (this.y.equals(other.y)) {
                return this.doublePoint();
            }
            return INFINITY; // P + (-P) = O
        }

        // lambda = (y2 - y1) / (x2 - x1)
        var dy = other.y.sub(this.y);
        var dx = other.x.sub(this.x);
        var lambda = dy.mul(dx.inv());

        // x3 = lambda^2 - x1 - x2
        var x3 = lambda.square().sub(this.x).sub(other.x);
        // y3 = lambda(x1 - x3) - y1
        var y3 = lambda.mul(this.x.sub(x3)).sub(this.y);

        return new G1Point(x3, y3);
    }

    /** Point doubling. */
    public G1Point doublePoint() {
        if (isInfinity()) return this;
        if (y.isZero()) return INFINITY;

        // lambda = (3*x^2) / (2*y)  [a=0 for BN254]
        var num = x.square().mul(Fp.of(3));
        var den = y.add(y);
        var lambda = num.mul(den.inv());

        var x3 = lambda.square().sub(x).sub(x);
        var y3 = lambda.mul(x.sub(x3)).sub(y);

        return new G1Point(x3, y3);
    }

    /** Scalar multiplication via double-and-add. */
    public G1Point scalarMul(BigInteger scalar) {
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
