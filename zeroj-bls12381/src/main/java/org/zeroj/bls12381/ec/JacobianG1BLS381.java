package org.zeroj.bls12381.ec;

import org.zeroj.bls12381.field.MontFp381;

import java.math.BigInteger;
import java.util.Objects;

/**
 * BLS12-381 G1 point in Jacobian coordinates.
 *
 * <p>BLS12-381 curve equation: y^2 = x^3 + 4 (short Weierstrass with a=0, b=4).</p>
 *
 * <p>Jacobian representation: a point (X, Y, Z) represents the affine point
 * (X/Z^2, Y/Z^3). The point at infinity is represented by Z = 0.</p>
 */
public final class JacobianG1BLS381 {

    /** Curve parameter b = 4. */
    private static final MontFp381 B = MontFp381.fromLong(4);

    private final MontFp381 x, y, z;

    private JacobianG1BLS381(MontFp381 x, MontFp381 y, MontFp381 z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    // --- Constants ---

    public static final JacobianG1BLS381 INFINITY = new JacobianG1BLS381(
            MontFp381.ONE, MontFp381.ONE, MontFp381.ZERO);

    /** BLS12-381 G1 generator. */
    public static final JacobianG1BLS381 GENERATOR = fromAffine(
            MontFp381.fromBigInteger(new BigInteger(
                    "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", 16)),
            MontFp381.fromBigInteger(new BigInteger(
                    "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1", 16)));

    // --- Factory ---

    public static JacobianG1BLS381 fromAffine(MontFp381 x, MontFp381 y) {
        if (x.isZero() && y.isZero()) return INFINITY;
        return new JacobianG1BLS381(x, y, MontFp381.ONE);
    }

    public static JacobianG1BLS381 fromAffine(BigInteger x, BigInteger y) {
        return fromAffine(MontFp381.fromBigInteger(x), MontFp381.fromBigInteger(y));
    }

    // --- Point operations ---

    public boolean isInfinity() { return z.isZero(); }

    public JacobianG1BLS381 negate() {
        if (isInfinity()) return this;
        return new JacobianG1BLS381(x, y.neg(), z);
    }

    /**
     * Point doubling using dbl-2009-l formula (a=0 optimization).
     */
    public JacobianG1BLS381 doublePoint() {
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

        return new JacobianG1BLS381(x3, y3, z3);
    }

    /** General point addition. */
    public JacobianG1BLS381 add(JacobianG1BLS381 other) {
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

        return new JacobianG1BLS381(x3, y3, z3);
    }

    /** Mixed addition with affine point (Z2 = 1). */
    public JacobianG1BLS381 addAffine(MontFp381 ax, MontFp381 ay) {
        if (this.isInfinity()) return fromAffine(ax, ay);
        if (ax.isZero() && ay.isZero()) return this;

        var z1z1 = this.z.square();
        var z1z1z1 = z1z1.mul(this.z);

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

        return new JacobianG1BLS381(x3, y3, z3);
    }

    /** Scalar multiplication using double-and-add (MSB-first). Not constant-time. */
    public JacobianG1BLS381 scalarMul(BigInteger scalar) {
        if (scalar.signum() == 0) return INFINITY;
        if (scalar.signum() < 0) return negate().scalarMul(scalar.negate());
        if (this.isInfinity()) return INFINITY;

        JacobianG1BLS381 result = INFINITY;
        JacobianG1BLS381 base = this;

        for (int i = scalar.bitLength() - 1; i >= 0; i--) {
            result = result.doublePoint();
            if (scalar.testBit(i)) result = result.add(base);
        }
        return result;
    }

    /**
     * Secret-scalar multiplication {@code [scalar mod r]·this} with additive scalar splitting and a
     * fixed operation schedule (ADR-0062 D1, r4).
     *
     * <p>The scalar {@code k} is reduced mod {@code r} and split into a fresh uniform share
     * {@code k₁ ∈ [0, r)} and {@code k₂ = (k − k₁) mod r} (Clavier–Joye, CHES 2001). Each share is
     * uniform on its own, whatever {@code k} is, and is recoded to exactly
     * {@value SecretLadder#WIDTH} bits; a Montgomery ladder then runs from {@code (P, 2P)} for
     * exactly {@value SecretLadder#ITERATIONS} iterations of one addition and one doubling per share,
     * and the two results are added. There is no zero-scalar early return. The operation count does
     * not depend on the scalar, and because each ladder sees a uniform scalar, a small or
     * near-{@code r} secret no longer drives it through identity intermediates (ADR-0062 F12).</p>
     *
     * <p><b>Allowed exceptions.</b> The final addition {@code [k₁]P + [k₂]P} takes a special branch
     * for {@code k ≡ 0} (the result is the identity, and {@code toAffine} then skips its inversion)
     * and, with probability {@code 1/r} each, when {@code k₁ = k₂}, {@code k₁ = 0} or
     * {@code k₂ = 0}.</p>
     *
     * <p>It is <b>not</b> a JVM constant-time guarantee: the per-bit selection is a Java branch, and
     * {@link BigInteger} arithmetic, field reductions, JIT and GC remain variable-time. Secret-bearing
     * generation stays offline/isolated only.</p>
     *
     * <p>The recoding is correct only for points in the prime-order subgroup, so this method checks
     * that the point is on the curve and in the subgroup, and rejects any other point. A failure
     * of the randomness source propagates; there is no unsplit fallback.</p>
     *
     * @param scalar any scalar with {@code bitLength() <= 256}; it is reduced mod {@code r}
     * @throws IllegalArgumentException if the scalar is wider than 256 bits or the point is not on
     *         the curve and in the subgroup
     */
    public JacobianG1BLS381 ctScalarMul(BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        if (scalar.bitLength() > 256) {
            throw new IllegalArgumentException("ctScalarMul scalar must fit in 256 bits");
        }
        if (this.isInfinity()) return INFINITY; // the base is public
        // On the curve first: the group-law formulas never use b, so without this a point on
        // another curve with r-torsion would be accepted (ADR-0062 M5 review).
        if (!toAffine().isOnCurve() || !scalarMul(G1Point.R).isInfinity()) {
            throw new IllegalArgumentException("ctScalarMul base must be on the curve and in the prime-order subgroup");
        }
        return ctScalarMulInSubgroup(scalar, SecretLadder.SECURE);
    }

    /**
     * {@link #ctScalarMul} for a base the caller has already checked to be in the prime-order
     * subgroup (the {@code G1Point} wrapper validates it). Package-private; the share source is a test
     * seam.
     */
    JacobianG1BLS381 ctScalarMulInSubgroup(BigInteger scalar, SecretLadder.ShareSource source) {
        if (this.isInfinity()) return INFINITY;
        BigInteger[] shares = SecretLadder.split(scalar.mod(G1Point.R), source);
        JacobianG1BLS381 a = fixedLadder(SecretLadder.recode(shares[0]));
        JacobianG1BLS381 b = fixedLadder(SecretLadder.recode(shares[1]));
        JacobianG1BLS381 sum = a.add(b);
        SecretLadder.ScheduleObserver observer = SecretLadder.observer();
        if (observer != null && (a.isInfinity() || b.isInfinity() || sum.isInfinity()
                || shares[0].equals(shares[1]))) {
            observer.combinationSpecial();
        }
        return sum;
    }

    /**
     * Montgomery ladder over a {@value SecretLadder#WIDTH}-bit recoded share whose top bit is set, from
     * {@code (P, 2P)}: invariant {@code r1 − r0 = P}, {@code r0 = [prefix]P}. Each iteration does
     * one addition and one doubling; the bit selects which accumulator receives which result.
     */
    private JacobianG1BLS381 fixedLadder(BigInteger kHat) {
        SecretLadder.ScheduleObserver observer = SecretLadder.observer();
        if (observer != null) observer.scheduleStarted(SecretLadder.ITERATIONS);
        JacobianG1BLS381 r0 = this;
        JacobianG1BLS381 r1 = this.doublePoint();
        for (int i = SecretLadder.WIDTH - 2; i >= 0; i--) {
            JacobianG1BLS381 sum = r0.add(r1);
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

    public AffineG1 toAffine() {
        if (isInfinity()) return AffineG1.INFINITY;
        var zInv = z.inverse();
        var zInv2 = zInv.square();
        var zInv3 = zInv2.mul(zInv);
        return new AffineG1(x.mul(zInv2), y.mul(zInv3));
    }

    /** Affine G1 point representation. */
    public record AffineG1(MontFp381 x, MontFp381 y) {
        public static final AffineG1 INFINITY = new AffineG1(MontFp381.ZERO, MontFp381.ZERO);

        public boolean isInfinity() { return x.isZero() && y.isZero(); }

        /** Check if on curve y^2 = x^3 + 4. */
        public boolean isOnCurve() {
            if (isInfinity()) return true;
            var lhs = y.square();
            var rhs = x.square().mul(x).add(B);
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
