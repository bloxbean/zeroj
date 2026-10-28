package org.zeroj.bls12381.ec;

import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.bls12381.field.MontFp2_381;

import java.math.BigInteger;
import java.util.Objects;

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

    /**
     * Secret-scalar multiplication {@code [scalar mod r]·this} with a fixed, blinded operation
     * schedule (ADR-0062 D1).
     *
     * <p>The scalar is reduced mod {@code r} and blinded to {@code k̂ = k + m·r} with a fresh
     * 64-bit-entropy {@code m}, chosen so that {@code k̂} always has exactly
     * {@value SecretLadder#WIDTH} bits. A Montgomery ladder then runs from {@code (P, 2P)} for
     * exactly {@value SecretLadder#ITERATIONS} iterations of one addition and one doubling. There
     * is no zero-scalar early return. This removes the scalar's bit length from the operation
     * count, and the blinding changes the per-bit pattern on every call.</p>
     *
     * <p>It is <b>not</b> a JVM constant-time guarantee: the per-bit selection is a Java branch, and
     * {@link BigInteger} arithmetic, field reductions, JIT and GC remain variable-time. Secret-bearing
     * generation stays offline/isolated only.</p>
     *
     * <p>The blinding is correct only for points in the prime-order subgroup, so this method checks
     * subgroup membership first and rejects any other point. A failure of the randomness source
     * propagates; there is no unblinded fallback.</p>
     *
     * @param scalar any scalar with {@code bitLength() <= 256}; it is reduced mod {@code r}
     * @throws IllegalArgumentException if the scalar is wider than 256 bits or the point is not in
     *         the subgroup
     */
    public JacobianG2BLS381 ctScalarMul(BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        if (scalar.bitLength() > 256) {
            throw new IllegalArgumentException("ctScalarMul scalar must fit in 256 bits");
        }
        if (this.isInfinity()) return INFINITY; // the base is public
        if (!scalarMul(G1Point.R).isInfinity()) {
            throw new IllegalArgumentException("ctScalarMul base must be in the prime-order subgroup");
        }
        return ctScalarMulInSubgroup(scalar, SecretLadder.SECURE);
    }

    /**
     * {@link #ctScalarMul} for a base the caller has already checked to be in the prime-order
     * subgroup (the {@code G2Point} wrapper validates it). Package-private; the blinding source is a test
     * seam.
     */
    JacobianG2BLS381 ctScalarMulInSubgroup(BigInteger scalar, SecretLadder.BlindingSource source) {
        if (this.isInfinity()) return INFINITY;
        BigInteger kHat = SecretLadder.blind(scalar.mod(G1Point.R), source);
        return fixedLadder(kHat);
    }

    /**
     * Montgomery ladder over a {@value SecretLadder#WIDTH}-bit scalar whose top bit is set, from
     * {@code (P, 2P)}: invariant {@code r1 − r0 = P}, {@code r0 = [prefix]P}. Each iteration does
     * one addition and one doubling; the bit selects which accumulator receives which result.
     */
    private JacobianG2BLS381 fixedLadder(BigInteger kHat) {
        SecretLadder.ScheduleObserver observer = SecretLadder.observer();
        if (observer != null) observer.scheduleStarted(SecretLadder.ITERATIONS);
        JacobianG2BLS381 r0 = this;
        JacobianG2BLS381 r1 = this.doublePoint();
        for (int i = SecretLadder.WIDTH - 2; i >= 0; i--) {
            JacobianG2BLS381 sum = r0.add(r1);
            boolean special = observer != null && (r0.isInfinity() || r1.isInfinity() || sum.isInfinity());
            if (kHat.testBit(i)) {
                r0 = sum;
                r1 = r1.doublePoint();
            } else {
                r1 = sum;
                r0 = r0.doublePoint();
            }
            if (observer != null) {
                observer.addition();
                observer.doubling();
                if (special) observer.specialCase(i);
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

    /**
     * {@link #toAffine()} for a block of points with <b>one</b> Fp2 inversion total
     * (Montgomery's trick, ADR-0035 M4) — the per-point inversion dominates bulk affine
     * conversion (e.g. trusted-setup key generation). Result {@code i} equals
     * {@code points[i].toAffine()} exactly; {@code null}/infinity entries yield
     * {@link AffineG2#INFINITY}.
     */
    public static AffineG2[] batchToAffine(JacobianG2BLS381[] points, int n) {
        AffineG2[] out = new AffineG2[n];
        MontFp2_381[] before = new MontFp2_381[n]; // product of non-infinity z's preceding i
        MontFp2_381 acc = null;
        for (int i = 0; i < n; i++) {
            if (points[i] == null || points[i].isInfinity()) {
                out[i] = AffineG2.INFINITY;
                continue;
            }
            before[i] = acc;
            acc = acc == null ? points[i].z : acc.mul(points[i].z);
        }
        if (acc == null) return out; // all infinity

        MontFp2_381 inv = acc.inverse(); // the only inversion
        for (int i = n - 1; i >= 0; i--) {
            if (out[i] != null) continue; // infinity slot, already filled
            MontFp2_381 zInv = before[i] == null ? inv : inv.mul(before[i]);
            MontFp2_381 zInv2 = zInv.square();
            MontFp2_381 zInv3 = zInv2.mul(zInv);
            out[i] = new AffineG2(points[i].x.mul(zInv2), points[i].y.mul(zInv3));
            inv = inv.mul(points[i].z);
        }
        return out;
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
