package com.bloxbean.cardano.zeroj.crypto.ec;

import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp2_254;

import java.math.BigInteger;

/**
 * BN254 G2 point in Jacobian coordinates over Fp2.
 *
 * <p>G2 is defined on the sextic twist of the BN254 curve over Fp2:
 * y^2 = x^3 + b' where b' = 3/(9+u) in Fp2.</p>
 *
 * <p>Same Jacobian formulas as G1 but all field operations are in Fp2.</p>
 */
public final class JacobianG2BN254 {

    /** Twist parameter b' = 3/(9+u) in Fp2. */
    private static final MontFp2_254 B_TWIST;
    static {
        // b' = 3*(9-u)/82  since (9+u)^{-1} = (9-u)/(9^2+1^2) = (9-u)/82
        BigInteger p = MontFp254.modulus();
        BigInteger inv82 = BigInteger.valueOf(82).modInverse(p);
        BigInteger bRe = BigInteger.valueOf(27).multiply(inv82).mod(p);   // 3*9/82
        BigInteger bIm = p.subtract(BigInteger.valueOf(3).multiply(inv82).mod(p)); // -3/82
        B_TWIST = MontFp2_254.of(bRe, bIm);
    }

    private final MontFp2_254 x, y, z;

    private JacobianG2BN254(MontFp2_254 x, MontFp2_254 y, MontFp2_254 z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    // --- Constants ---

    public static final JacobianG2BN254 INFINITY = new JacobianG2BN254(
            MontFp2_254.ONE, MontFp2_254.ONE, MontFp2_254.ZERO);

    /** BN254 G2 generator (standard, EIP-197 compatible). */
    public static final JacobianG2BN254 GENERATOR = fromAffine(
            MontFp2_254.of(
                    new BigInteger("10857046999023057135944570762232829481370756359578518086990519993285655852781"),
                    new BigInteger("11559732032986387107991004021392285783925812861821192530917403151452391805634")),
            MontFp2_254.of(
                    new BigInteger("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                    new BigInteger("4082367875863433681332203403145435568316851327593401208105741076214120093531")));

    // --- Factory ---

    public static JacobianG2BN254 fromAffine(MontFp2_254 x, MontFp2_254 y) {
        if (x.isZero() && y.isZero()) return INFINITY;
        return new JacobianG2BN254(x, y, MontFp2_254.ONE);
    }

    // --- Point operations ---

    public boolean isInfinity() { return z.isZero(); }

    public JacobianG2BN254 negate() {
        if (isInfinity()) return this;
        return new JacobianG2BN254(x, y.neg(), z);
    }

    /** Point doubling (a=0 optimization — same formula as G1 but over Fp2). */
    public JacobianG2BN254 doublePoint() {
        if (isInfinity()) return this;
        if (y.isZero()) return INFINITY;

        var a = x.square();
        var b = y.square();
        var c = b.square();
        var d = x.add(b).square().sub(a).sub(c).dbl();
        var e = a.add(a).add(a); // 3*x^2 (a=0, so no +a*z^4 term)
        var f = e.square();

        var x3 = f.sub(d.dbl());
        var c8 = c.dbl().dbl().dbl();
        var y3 = e.mul(d.sub(x3)).sub(c8);
        var z3 = y.mul(z).dbl();

        return new JacobianG2BN254(x3, y3, z3);
    }

    /** General point addition. */
    public JacobianG2BN254 add(JacobianG2BN254 other) {
        if (this.isInfinity()) return other;
        if (other.isInfinity()) return this;

        var z1z1 = this.z.square();
        var z2z2 = other.z.square();
        var u1 = this.x.mul(z2z2);
        var u2 = other.x.mul(z1z1);
        var s1 = this.y.mul(z2z2).mul(other.z);
        var s2 = other.y.mul(z1z1).mul(this.z);

        var h = u2.sub(u1);
        var r = s2.sub(s1);

        if (h.isZero()) {
            if (r.isZero()) return this.doublePoint();
            else return INFINITY;
        }

        var hh = h.square();
        var hhh = hh.mul(h);
        var v = u1.mul(hh);

        var x3 = r.square().sub(hhh).sub(v.dbl());
        var y3 = r.mul(v.sub(x3)).sub(s1.mul(hhh));
        var z3 = this.z.mul(other.z).mul(h);

        return new JacobianG2BN254(x3, y3, z3);
    }

    /** Scalar multiplication. */
    public JacobianG2BN254 scalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().scalarMul(scalar.negate());
        if (this.isInfinity()) return INFINITY;

        JacobianG2BN254 result = INFINITY;
        JacobianG2BN254 base = this;

        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = result.doublePoint();
            if (scalar.testBit(i)) result = result.add(base);
        }
        return result;
    }

    /** Convert to affine (X/Z^2, Y/Z^3). */
    public AffineG2 toAffine() {
        if (isInfinity()) return AffineG2.INFINITY;
        var zInv = z.inverse();
        var zInv2 = zInv.square();
        var zInv3 = zInv2.mul(zInv);
        return new AffineG2(x.mul(zInv2), y.mul(zInv3));
    }

    /** Affine G2 point. */
    public record AffineG2(MontFp2_254 x, MontFp2_254 y) {
        public static final AffineG2 INFINITY = new AffineG2(MontFp2_254.ZERO, MontFp2_254.ZERO);
        public boolean isInfinity() { return x.isZero() && y.isZero(); }

        /** Check on twist curve: y^2 = x^3 + b'. */
        public boolean isOnCurve() {
            if (isInfinity()) return true;
            var lhs = y.square();
            var rhs = x.square().mul(x).add(B_TWIST);
            return lhs.equals(rhs);
        }
    }

    @Override
    public String toString() {
        if (isInfinity()) return "G2(infinity)";
        var aff = toAffine();
        return "G2(" + aff.x() + ", " + aff.y() + ")";
    }
}
