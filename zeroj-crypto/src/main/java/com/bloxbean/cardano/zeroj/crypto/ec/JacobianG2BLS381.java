package com.bloxbean.cardano.zeroj.crypto.ec;

import com.bloxbean.cardano.zeroj.crypto.field.MontFp381;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp2_381;

import java.math.BigInteger;

/**
 * BLS12-381 G2 point in Jacobian coordinates over Fp2.
 *
 * <p>G2 is defined on the sextic twist of the BLS12-381 curve over Fp2:
 * y^2 = x^3 + 4(1+u) where Fp2 = Fp[u]/(u^2+1).</p>
 *
 * <p>Same Jacobian formulas as G1 but all field operations are in Fp2.</p>
 */
public final class JacobianG2BLS381 {

    /** Twist parameter b' = 4(1+u) in Fp2. */
    static final MontFp2_381 B_TWIST = MontFp2_381.of(
            MontFp381.fromLong(4), MontFp381.fromLong(4));

    private final MontFp2_381 x, y, z;

    private JacobianG2BLS381(MontFp2_381 x, MontFp2_381 y, MontFp2_381 z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    // --- Constants ---

    public static final JacobianG2BLS381 INFINITY = new JacobianG2BLS381(
            MontFp2_381.ONE, MontFp2_381.ONE, MontFp2_381.ZERO);

    /** BLS12-381 G2 generator (standard). */
    public static final JacobianG2BLS381 GENERATOR = fromAffine(
            MontFp2_381.of(
                    new BigInteger("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8", 16),
                    new BigInteger("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e", 16)),
            MontFp2_381.of(
                    new BigInteger("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801", 16),
                    new BigInteger("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be", 16)));

    // --- Factory ---

    public static JacobianG2BLS381 fromAffine(MontFp2_381 x, MontFp2_381 y) {
        if (x.isZero() && y.isZero()) return INFINITY;
        return new JacobianG2BLS381(x, y, MontFp2_381.ONE);
    }

    // --- Point operations ---

    public boolean isInfinity() { return z.isZero(); }

    public JacobianG2BLS381 negate() {
        if (isInfinity()) return this;
        return new JacobianG2BLS381(x, y.neg(), z);
    }

    /** Point doubling (a=0 optimization over Fp2). */
    public JacobianG2BLS381 doublePoint() {
        if (isInfinity()) return this;
        if (y.isZero()) return INFINITY;

        var a = x.square();
        var b = y.square();
        var c = b.square();
        var d = x.add(b).square().sub(a).sub(c).dbl();
        var e = a.add(a).add(a); // 3*x^2
        var f = e.square();

        var x3 = f.sub(d.dbl());
        var c8 = c.dbl().dbl().dbl();
        var y3 = e.mul(d.sub(x3)).sub(c8);
        var z3 = y.mul(z).dbl();

        return new JacobianG2BLS381(x3, y3, z3);
    }

    /** General point addition. */
    public JacobianG2BLS381 add(JacobianG2BLS381 other) {
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

        return new JacobianG2BLS381(x3, y3, z3);
    }

    /** Scalar multiplication (not constant-time). */
    public JacobianG2BLS381 scalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().scalarMul(scalar.negate());
        if (this.isInfinity()) return INFINITY;

        JacobianG2BLS381 result = INFINITY;
        JacobianG2BLS381 base = this;

        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = result.doublePoint();
            if (scalar.testBit(i)) result = result.add(base);
        }
        return result;
    }

    /** Constant-time scalar multiplication using Montgomery ladder. */
    public JacobianG2BLS381 ctScalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().ctScalarMul(scalar.negate());
        if (this.isInfinity()) return INFINITY;

        JacobianG2BLS381 r0 = INFINITY;
        JacobianG2BLS381 r1 = this;

        for (int i = 255; i >= 0; i--) {
            if (scalar.testBit(i)) {
                r0 = r0.add(r1);
                r1 = r1.doublePoint();
            } else {
                r1 = r0.add(r1);
                r0 = r0.doublePoint();
            }
        }
        return r0;
    }

    // --- Conversion ---

    public AffineG2 toAffine() {
        if (isInfinity()) return AffineG2.INFINITY;
        var zInv = z.inverse();
        var zInv2 = zInv.square();
        var zInv3 = zInv2.mul(zInv);
        return new AffineG2(x.mul(zInv2), y.mul(zInv3));
    }

    /** Affine G2 point. */
    public record AffineG2(MontFp2_381 x, MontFp2_381 y) {
        public static final AffineG2 INFINITY = new AffineG2(MontFp2_381.ZERO, MontFp2_381.ZERO);
        public boolean isInfinity() { return x.isZero() && y.isZero(); }

        /** Check on twist curve: y^2 = x^3 + 4(1+u). */
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
