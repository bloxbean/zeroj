package org.zeroj.circuit.lib.jubjub;

import org.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * Jubjub point arithmetic in extended twisted-Edwards coordinates over Montgomery-form
 * BLS12-381 scalar-field elements. Jubjub's base field is that field, so {@link MontFr381}'s
 * limb arithmetic applies directly.
 *
 * <p><b>Never for a secret scalar.</b> Every operation is variable-time and branches on its
 * inputs. Use it for public data: decoded points, subgroup checks, homomorphic sums of
 * ciphertexts, and verification equations. Decryption also uses it on secret-derived
 * <i>points</i> (unmasking {@code B − [sk]·A}, and the plaintext search on {@code [m]·G}).
 * There it inherits decryption's compatibility/offline classification (ADR-0039 §3.1).
 * Multiplications by a secret <i>scalar</i> always go through
 * {@link JubjubPoint#scalarMulSecretBlindedBestEffort}.
 *
 * <p>The addition and doubling formulas are exactly those of {@link JubjubPoint#add} and
 * {@link JubjubPoint#doubled} (HWCD unified addition and dedicated doubling for {@code a = −1}),
 * so the two classes compute identical projective representatives. {@code FastJubjubPointTest}
 * checks that differentially.
 */
final class FastJubjubPoint {

    private static final MontFr381 TWO_D = MontFr381.fromBigInteger(JubjubCurve.TWO_D);
    private static final MontFr381 TWO = MontFr381.fromLong(2);

    static final FastJubjubPoint IDENTITY =
            new FastJubjubPoint(MontFr381.ZERO, MontFr381.ONE, MontFr381.ONE, MontFr381.ZERO);

    static final FastJubjubPoint GENERATOR = of(JubjubPoint.SUBGROUP_GENERATOR);

    final MontFr381 u;
    final MontFr381 v;
    final MontFr381 z;
    final MontFr381 t;

    private FastJubjubPoint(MontFr381 u, MontFr381 v, MontFr381 z, MontFr381 t) {
        this.u = u;
        this.v = v;
        this.z = z;
        this.t = t;
    }

    /** Converts a point, keeping its projective representative. */
    static FastJubjubPoint of(JubjubPoint point) {
        Objects.requireNonNull(point, "point");
        return new FastJubjubPoint(
                MontFr381.fromBigInteger(point.u()),
                MontFr381.fromBigInteger(point.v()),
                MontFr381.fromBigInteger(point.z()),
                MontFr381.fromBigInteger(point.t()));
    }

    /** Converts back to a normalized {@link JubjubPoint} (one inversion). */
    JubjubPoint toJubjubPoint() {
        MontFr381 zInverse = z.inverse();
        return JubjubPoint.fromAffine(u.mul(zInverse).toBigInteger(), v.mul(zInverse).toBigInteger());
    }

    FastJubjubPoint add(FastJubjubPoint other) {
        MontFr381 rA = v.sub(u).mul(other.v.sub(other.u));
        MontFr381 rB = v.add(u).mul(other.v.add(other.u));
        MontFr381 rC = t.mul(TWO_D).mul(other.t);
        MontFr381 rD = z.mul(TWO).mul(other.z);
        MontFr381 rE = rB.sub(rA);
        MontFr381 rF = rD.sub(rC);
        MontFr381 rG = rD.add(rC);
        MontFr381 rH = rB.add(rA);
        return new FastJubjubPoint(rE.mul(rF), rG.mul(rH), rF.mul(rG), rE.mul(rH));
    }

    FastJubjubPoint doubled() {
        MontFr381 rA = u.square();
        MontFr381 rB = v.square();
        MontFr381 zz = z.square();
        MontFr381 rC = zz.add(zz);
        MontFr381 rD = rA.neg();
        MontFr381 sum = u.add(v);
        MontFr381 rE = sum.square().sub(rA).sub(rB);
        MontFr381 rG = rD.add(rB);
        MontFr381 rF = rG.sub(rC);
        MontFr381 rH = rD.sub(rB);
        return new FastJubjubPoint(rE.mul(rF), rG.mul(rH), rF.mul(rG), rE.mul(rH));
    }

    FastJubjubPoint negate() {
        return new FastJubjubPoint(u.neg(), v, z, t.neg());
    }

    FastJubjubPoint subtract(FastJubjubPoint other) {
        return add(other.negate());
    }

    /**
     * {@code [k]·this} for a <b>public</b> non-negative scalar, by left-to-right
     * double-and-add. The scalar is not reduced mod {@code l}, so the result is exact for
     * points outside the prime-order subgroup too.
     */
    FastJubjubPoint scalarMulPublic(BigInteger k) {
        Objects.requireNonNull(k, "k");
        JubjubPoint.notePublicMultiplication();
        if (k.signum() < 0) {
            throw new IllegalArgumentException("public scalar must be non-negative");
        }
        FastJubjubPoint result = IDENTITY;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            result = result.doubled();
            if (k.testBit(i)) {
                result = result.add(this);
            }
        }
        return result;
    }

    /** {@code [k]·this} for a small public multiplier. */
    FastJubjubPoint scalarMulPublic(long k) {
        JubjubPoint.notePublicMultiplication();
        if (k < 0) {
            throw new IllegalArgumentException("public scalar must be non-negative");
        }
        FastJubjubPoint result = IDENTITY;
        for (int i = 63 - Long.numberOfLeadingZeros(k); i >= 0; i--) {
            result = result.doubled();
            if (((k >>> i) & 1L) != 0) {
                result = result.add(this);
            }
        }
        return result;
    }

    /** True iff this is the identity: {@code U = 0} and {@code V = Z}. */
    boolean isIdentity() {
        return u.isZero() && v.equals(z);
    }

    /** True iff {@code [l]·this} is the identity. */
    boolean isInPrimeOrderSubgroup() {
        return scalarMulPublic(SUBGROUP_ORDER).isIdentity();
    }

    /** Projective equality: {@code U₁·Z₂ = U₂·Z₁} and {@code V₁·Z₂ = V₂·Z₁}. */
    boolean projectiveEquals(FastJubjubPoint other) {
        return u.mul(other.z).equals(other.u.mul(z)) && v.mul(other.z).equals(other.v.mul(z));
    }

    /** Subgroup check for a host point, on the fast path. */
    static boolean isInPrimeOrderSubgroup(JubjubPoint point) {
        return of(point).isInPrimeOrderSubgroup();
    }

    /** Sum of host points on the fast path; returns a normalized point. */
    static JubjubPoint sum(Iterable<JubjubPoint> points) {
        FastJubjubPoint acc = IDENTITY;
        for (JubjubPoint point : points) {
            acc = acc.add(of(point));
        }
        return acc.toJubjubPoint();
    }

    /**
     * Replaces {@code zs[i]} by its inverse for every {@code i < count}, with one field inversion
     * (Montgomery's trick). Throws if any element is zero: a single zero would otherwise poison
     * every result of the batch.
     */
    static void batchInvert(MontFr381[] zs, int count, MontFr381[] scratch) {
        if (count == 0) {
            return;
        }
        MontFr381 acc = MontFr381.ONE;
        for (int i = 0; i < count; i++) {
            if (zs[i].isZero()) {
                throw new IllegalStateException("batch inversion of a zero element");
            }
            scratch[i] = acc;
            acc = acc.mul(zs[i]);
        }
        MontFr381 inverse = acc.inverse();
        for (int i = count - 1; i >= 0; i--) {
            MontFr381 zi = zs[i];
            zs[i] = inverse.mul(scratch[i]);
            inverse = inverse.mul(zi);
        }
    }
}
