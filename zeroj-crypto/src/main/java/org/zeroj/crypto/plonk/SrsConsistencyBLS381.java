package org.zeroj.crypto.plonk;

import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.bls12381.pairing.BLS12381Pairing;
import org.zeroj.crypto.msm.PippengerBLS381;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;

/**
 * Batched random-linear-combination (RLC) SRS consistency verifier for BLS12-381 PlonK (ADR-0068).
 *
 * <p>Given validated non-infinity prime-order subgroup points {@code tauG1[0..count-1]} and
 * {@code tauG2[0..1]}, verifies {@code tauG1[0] == G1}, {@code tauG2[0] == G2}, and
 * {@code e(tauG1[i], G2) == e(tauG1[i - 1], tauG2[1])} for all {@code 1 <= i < count} using a
 * single two-pairing check over a {@link SecureRandom} challenge {@code r ∈ F_r \ {0}}.</p>
 */
final class SrsConsistencyBLS381 {

    private static final BigInteger FR = MontFr381.modulus();
    private static final SecureRandom RNG = new SecureRandom();
    private static final AffineG1 G1_GEN = JacobianG1BLS381.GENERATOR.toAffine();
    private static final AffineG2 G2_GEN = JacobianG2BLS381.GENERATOR.toAffine();

    private record VerifiedSnapshot(AffineG1[] tauG1, AffineG2[] tauG2) {}

    /**
     * Weak cache of SRS instances verified by {@link PtauImporterBLS381}, storing defensive
     * snapshots of the verified arrays so {@link PlonKSetupBLS381} avoids duplicate subgroup and
     * pairing verification only when no element has been mutated after import.
     */
    private static final Map<PtauImporterBLS381.SRS, VerifiedSnapshot> VERIFIED =
            Collections.synchronizedMap(new WeakHashMap<>());

    private SrsConsistencyBLS381() {}

    static void verifyConsistency(AffineG1[] tauG1, AffineG2[] tauG2, int count, String label) {
        verifyConsistency(tauG1, tauG2, count, label, RNG);
    }

    static void verifyConsistency(
            AffineG1[] tauG1,
            AffineG2[] tauG2,
            int count,
            String label,
            SecureRandom rng) {
        if (count <= 0 || tauG1 == null || tauG1.length < count) {
            throw new IllegalArgumentException(label + " G1 array is shorter than count " + count);
        }
        if (tauG2 == null || tauG2.length < 2) {
            throw new IllegalArgumentException(label + " G2 array must contain at least 2 points");
        }
        if (!G1_GEN.equals(tauG1[0])) {
            throw new IllegalArgumentException(label + " G1 generator anchor mismatch");
        }
        if (!G2_GEN.equals(tauG2[0])) {
            throw new IllegalArgumentException(label + " G2 generator anchor mismatch");
        }
        if (count == 1) {
            return;
        }

        int pairs = count - 1;
        MontFr381 challenge = randomNonZeroFr(rng);
        BigInteger[] weights = new BigInteger[pairs];
        MontFr381 power = MontFr381.ONE;
        for (int j = 0; j < pairs; j++) {
            weights[j] = power.toBigInteger();
            power = power.mul(challenge);
        }

        AffineG1[] shifted = Arrays.copyOfRange(tauG1, 1, count);
        AffineG1[] base = Arrays.copyOfRange(tauG1, 0, count - 1);
        AffineG1 lhsSum = PippengerBLS381.msm(shifted, weights).toAffine();
        AffineG1 rhsSum = PippengerBLS381.msm(base, weights).toAffine();

        boolean consistent = BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(lhsSum), toG1(rhsSum).negate()},
                new G2Point[]{toG2(tauG2[0]), toG2(tauG2[1])});
        if (!consistent) {
            throw new IllegalArgumentException(label + " SRS powers are inconsistent");
        }
    }

    static void recordVerified(PtauImporterBLS381.SRS srs) {
        Objects.requireNonNull(srs, "srs");
        VERIFIED.put(srs, new VerifiedSnapshot(srs.tauG1().clone(), Arrays.copyOf(srs.tauG2(), 2)));
    }

    static boolean isUnmodifiedVerified(PtauImporterBLS381.SRS srs, int requiredG1) {
        VerifiedSnapshot snap = VERIFIED.get(srs);
        if (snap == null) {
            return false;
        }
        AffineG1[] tauG1 = srs.tauG1();
        AffineG2[] tauG2 = srs.tauG2();
        if (tauG1 == null || tauG2 == null
                || tauG1.length < requiredG1
                || snap.tauG1.length < requiredG1
                || tauG2.length < 2) {
            return false;
        }
        return Arrays.equals(tauG1, 0, requiredG1, snap.tauG1, 0, requiredG1)
                && Objects.equals(tauG2[0], snap.tauG2[0])
                && Objects.equals(tauG2[1], snap.tauG2[1]);
    }

    static G1Point toG1(AffineG1 point) {
        if (point == null || point.isInfinity()) {
            return G1Point.INFINITY;
        }
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    static G2Point toG2(AffineG2 point) {
        if (point == null || point.isInfinity()) {
            return G2Point.INFINITY;
        }
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    private static MontFr381 randomNonZeroFr(SecureRandom rng) {
        byte[] bytes = new byte[32];
        BigInteger value;
        do {
            rng.nextBytes(bytes);
            value = new BigInteger(1, bytes);
        } while (value.signum() == 0 || value.compareTo(FR) >= 0);
        return MontFr381.fromBigInteger(value);
    }
}
