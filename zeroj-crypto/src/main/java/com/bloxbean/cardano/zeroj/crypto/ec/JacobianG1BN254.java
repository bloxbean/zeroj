package com.bloxbean.cardano.zeroj.crypto.ec;

import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;

import java.math.BigInteger;

/**
 * BN254 G1 point in Jacobian coordinates.
 *
 * <p>Jacobian representation: a point (X, Y, Z) represents the affine point
 * (X/Z^2, Y/Z^3). The point at infinity is represented by Z = 0.</p>
 *
 * <p>BN254 curve equation: y^2 = x^3 + 3 (short Weierstrass with a=0, b=3).</p>
 *
 * <p>Using Jacobian coordinates eliminates field inversions from the inner loop
 * of scalar multiplication. A single inversion is only needed at the end
 * when converting back to affine coordinates.</p>
 *
 * <h3>Operation costs (M = Fp mul, S = Fp square)</h3>
 * <ul>
 *   <li>Point addition (mixed, Z2=1): 8M + 3S</li>
 *   <li>Point addition (general): 12M + 4S</li>
 *   <li>Point doubling: 2M + 5S (using a=0 optimization, EFD dbl-2009-l)</li>
 *   <li>Compare: affine addition costs 1M + 1S + 1 inversion (~50x M)</li>
 * </ul>
 */
public final class JacobianG1BN254 {

    /** Curve parameter b = 3. */
    private static final MontFp254 B = MontFp254.THREE;

    /** 3*b = 9, used in doubling formula for a=0 curves. */
    private static final MontFp254 B3 = MontFp254.fromLong(9);

    private final MontFp254 x, y, z;

    private JacobianG1BN254(MontFp254 x, MontFp254 y, MontFp254 z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    // --- Constants ---

    /** Point at infinity (identity element). */
    public static final JacobianG1BN254 INFINITY = new JacobianG1BN254(
            MontFp254.ONE, MontFp254.ONE, MontFp254.ZERO);

    /** BN254 G1 generator point (1, 2). */
    public static final JacobianG1BN254 GENERATOR = fromAffine(
            MontFp254.ONE, MontFp254.TWO);

    // --- Factory ---

    /** Create from affine coordinates (x, y). */
    public static JacobianG1BN254 fromAffine(MontFp254 x, MontFp254 y) {
        if (x.isZero() && y.isZero()) return INFINITY;
        return new JacobianG1BN254(x, y, MontFp254.ONE);
    }

    /** Create from affine BigInteger coordinates. */
    public static JacobianG1BN254 fromAffine(BigInteger x, BigInteger y) {
        return fromAffine(MontFp254.fromBigInteger(x), MontFp254.fromBigInteger(y));
    }

    // --- Point operations ---

    public boolean isInfinity() {
        return z.isZero();
    }

    /**
     * Point negation: -(X, Y, Z) = (X, -Y, Z).
     */
    public JacobianG1BN254 negate() {
        if (isInfinity()) return this;
        return new JacobianG1BN254(x, y.neg(), z);
    }

    /**
     * Point doubling using the "dbl-2009-l" formula (a=0 optimization).
     *
     * <p>Cost: 1M + 5S + 1*a + 7add (for a=0: 2M + 5S + 6add)</p>
     * <p>Reference: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l</p>
     */
    public JacobianG1BN254 doublePoint() {
        if (isInfinity()) return this;
        if (y.isZero()) return INFINITY;

        // a = X1^2
        var a = x.square();
        // b = Y1^2
        var b = y.square();
        // c = b^2
        var c = b.square();
        // d = 2*((X1+b)^2 - a - c)
        var d = x.add(b).square().sub(a).sub(c).dbl();
        // e = 3*a (since curve a=0, this is 3*X1^2)
        var e = a.add(a).add(a);
        // f = e^2
        var f = e.square();

        // X3 = f - 2*d
        var x3 = f.sub(d.dbl());
        // Y3 = e*(d - X3) - 8*c
        var c8 = c.dbl().dbl().dbl();
        var y3 = e.mul(d.sub(x3)).sub(c8);
        // Z3 = 2*Y1*Z1
        var z3 = y.mul(z).dbl();

        return new JacobianG1BN254(x3, y3, z3);
    }

    /**
     * Point addition.
     *
     * <p>Handles all cases: infinity, equal points (doubling), negation.</p>
     * <p>Standard Jacobian addition formula for short Weierstrass curves (a=0).</p>
     */
    public JacobianG1BN254 add(JacobianG1BN254 other) {
        if (this.isInfinity()) return other;
        if (other.isInfinity()) return this;

        // U1 = X1*Z2^2, U2 = X2*Z1^2
        var z1z1 = this.z.square();
        var z2z2 = other.z.square();
        var u1 = this.x.mul(z2z2);
        var u2 = other.x.mul(z1z1);

        // S1 = Y1*Z2^3, S2 = Y2*Z1^3
        var s1 = this.y.mul(z2z2).mul(other.z);
        var s2 = other.y.mul(z1z1).mul(this.z);

        // H = U2 - U1
        var h = u2.sub(u1);
        // R = S2 - S1
        var r = s2.sub(s1);

        if (h.isZero()) {
            if (r.isZero()) {
                // Same point: double
                return this.doublePoint();
            } else {
                // Point and its negation: return infinity
                return INFINITY;
            }
        }

        var hh = h.square();
        var hhh = hh.mul(h);
        var v = u1.mul(hh);

        // X3 = R^2 - H^3 - 2*V
        var x3 = r.square().sub(hhh).sub(v.dbl());
        // Y3 = R*(V - X3) - S1*H^3
        var y3 = r.mul(v.sub(x3)).sub(s1.mul(hhh));
        // Z3 = Z1*Z2*H
        var z3 = this.z.mul(other.z).mul(h);

        return new JacobianG1BN254(x3, y3, z3);
    }

    /**
     * Mixed addition: add an affine point (Z2 = 1). Cheaper than general add.
     *
     * <p>Cost: 7M + 4S (vs 11M + 5S for general)</p>
     */
    public JacobianG1BN254 addAffine(MontFp254 ax, MontFp254 ay) {
        if (this.isInfinity()) return fromAffine(ax, ay);
        if (ax.isZero() && ay.isZero()) return this;

        // Z1^2, Z1^3
        var z1z1 = this.z.square();
        var z1z1z1 = z1z1.mul(this.z);

        // U1 = X1 (since Z2=1, U1 = X1*1 = X1 already in Jacobian)
        // Actually: U1 = X1, U2 = X2*Z1^2
        var u2 = ax.mul(z1z1);
        var s2 = ay.mul(z1z1z1);

        var h = u2.sub(this.x);
        var r = s2.sub(this.y);

        if (h.isZero()) {
            if (r.isZero()) return this.doublePoint();
            else return INFINITY;
        }

        var hh = h.square();
        var hhh = hh.mul(h);
        var v = this.x.mul(hh);

        var x3 = r.square().sub(hhh).sub(v.dbl());
        var y3 = r.mul(v.sub(x3)).sub(this.y.mul(hhh));
        var z3 = this.z.mul(h);

        return new JacobianG1BN254(x3, y3, z3);
    }

    /**
     * Scalar multiplication using double-and-add (MSB-first).
     */
    public JacobianG1BN254 scalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().scalarMul(scalar.negate());
        if (this.isInfinity()) return INFINITY;

        JacobianG1BN254 result = INFINITY;
        JacobianG1BN254 base = this;

        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = result.doublePoint();
            if (scalar.testBit(i)) {
                result = result.add(base);
            }
        }
        return result;
    }

    // --- Conversion ---

    /** Convert to affine coordinates (X/Z^2, Y/Z^3). Requires one field inversion. */
    public AffineG1 toAffine() {
        if (isInfinity()) return AffineG1.INFINITY;
        var zInv = z.inverse();
        var zInv2 = zInv.square();
        var zInv3 = zInv2.mul(zInv);
        return new AffineG1(x.mul(zInv2), y.mul(zInv3));
    }

    /** Affine G1 point representation. */
    public record AffineG1(MontFp254 x, MontFp254 y) {
        public static final AffineG1 INFINITY = new AffineG1(MontFp254.ZERO, MontFp254.ZERO);

        public boolean isInfinity() { return x.isZero() && y.isZero(); }

        /** Check if this point lies on the curve y^2 = x^3 + 3. */
        public boolean isOnCurve() {
            if (isInfinity()) return true;
            var lhs = y.square();
            var rhs = x.square().mul(x).add(MontFp254.THREE);
            return lhs.equals(rhs);
        }

        public BigInteger xBigInt() { return x.toBigInteger(); }
        public BigInteger yBigInt() { return y.toBigInteger(); }
    }

    @Override
    public String toString() {
        if (isInfinity()) return "G1(infinity)";
        var aff = toAffine();
        return "G1(" + aff.x().toBigInteger() + ", " + aff.y().toBigInteger() + ")";
    }
}
