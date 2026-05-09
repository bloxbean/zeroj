package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class PippengerBLS381Test {

    static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    static final Random RNG = new Random(381);

    @Test
    void msm_empty() {
        assertTrue(PippengerBLS381.msm(new AffineG1[0], new BigInteger[0]).isInfinity());
    }

    @Test
    void msm_singlePoint() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var result = PippengerBLS381.msm(new AffineG1[]{g}, new BigInteger[]{BigInteger.valueOf(42)});
        var expected = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(42));
        assertPointsEqual(expected, result);
    }

    @Test
    void msm_twoPoints_generator() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var result = PippengerBLS381.msm(
                new AffineG1[]{g, g},
                new BigInteger[]{BigInteger.valueOf(3), BigInteger.valueOf(7)});
        var expected = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.TEN);
        assertPointsEqual(expected, result);
    }

    @Test
    void msm_twoDistinctPoints() {
        var g = JacobianG1BLS381.GENERATOR;
        var twoG = g.doublePoint();
        // 5*G + 3*(2G) = 11*G
        var result = PippengerBLS381.msm(
                new AffineG1[]{g.toAffine(), twoG.toAffine()},
                new BigInteger[]{BigInteger.valueOf(5), BigInteger.valueOf(3)});
        assertPointsEqual(g.scalarMul(BigInteger.valueOf(11)), result);
    }

    @Test
    void msm_zeroScalar_skipped() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var result = PippengerBLS381.msm(
                new AffineG1[]{g, g},
                new BigInteger[]{BigInteger.ZERO, BigInteger.valueOf(5)});
        assertPointsEqual(JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(5)), result);
    }

    @Test
    void msm_allZeroScalars() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var result = PippengerBLS381.msm(
                new AffineG1[]{g, g, g},
                new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO});
        assertTrue(result.isInfinity());
    }

    @Test
    void msm_negativeScalar_matchesNaive() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var result = PippengerBLS381.msm(new AffineG1[]{g}, new BigInteger[]{BigInteger.valueOf(-5)});
        var expected = PippengerBLS381.naiveMsm(new AffineG1[]{g}, new BigInteger[]{BigInteger.valueOf(-5)});
        assertPointsEqual(expected, result);
    }

    @Test
    void msm_mixedNegativePositive() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var twoG = JacobianG1BLS381.GENERATOR.doublePoint().toAffine();
        // (-3)*G + 7*(2G) = -3G + 14G = 11G
        var result = PippengerBLS381.msm(
                new AffineG1[]{g, twoG},
                new BigInteger[]{BigInteger.valueOf(-3), BigInteger.valueOf(7)});
        assertPointsEqual(JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(11)), result);
    }

    @Test
    void msm_withInfinityPoints() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var result = PippengerBLS381.msm(
                new AffineG1[]{g, AffineG1.INFINITY},
                new BigInteger[]{BigInteger.valueOf(5), BigInteger.valueOf(3)});
        assertPointsEqual(JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(5)), result);
    }

    @Test
    void msm_largeScalars() {
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var twoG = JacobianG1BLS381.GENERATOR.doublePoint().toAffine();
        BigInteger s1 = new BigInteger("123456789012345678901234567890123456789");
        BigInteger s2 = new BigInteger("987654321098765432109876543210987654321");
        var result = PippengerBLS381.msm(new AffineG1[]{g, twoG}, new BigInteger[]{s1, s2});
        var expected = PippengerBLS381.naiveMsm(new AffineG1[]{g, twoG}, new BigInteger[]{s1, s2});
        assertPointsEqual(expected, result);
    }

    @Test
    void msm_4points_matchesNaive() { assertMsmMatchesNaive(4); }

    @Test
    void msm_8points_matchesNaive() { assertMsmMatchesNaive(8); }

    @Test
    void msm_16points_matchesNaive() { assertMsmMatchesNaive(16); }

    @Test
    void msm_32points_matchesNaive() { assertMsmMatchesNaive(32); }

    @Test
    void msm_resultOnCurve() {
        var points = generatePoints(10);
        var scalars = generateScalars(10);
        var result = PippengerBLS381.msm(points, scalars);
        if (!result.isInfinity()) {
            assertTrue(result.toAffine().isOnCurve(), "MSM result must be on BLS12-381 G1 curve");
        }
    }

    @Test
    void msm_mismatchedLengths_throws() {
        assertThrows(IllegalArgumentException.class, () ->
                PippengerBLS381.msm(
                        new AffineG1[]{JacobianG1BLS381.GENERATOR.toAffine()},
                        new BigInteger[]{BigInteger.ONE, BigInteger.TWO}));
    }

    // --- Helpers ---

    private void assertMsmMatchesNaive(int n) {
        var points = generatePoints(n);
        var scalars = generateScalars(n);
        var pipResult = PippengerBLS381.msm(points, scalars);
        var naiveResult = PippengerBLS381.naiveMsm(points, scalars);
        assertPointsEqual(naiveResult, pipResult);
    }

    private AffineG1[] generatePoints(int n) {
        var points = new AffineG1[n];
        var base = JacobianG1BLS381.GENERATOR;
        for (int i = 0; i < n; i++) {
            points[i] = base.scalarMul(BigInteger.valueOf(i + 1)).toAffine();
        }
        return points;
    }

    private BigInteger[] generateScalars(int n) {
        var scalars = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            byte[] bytes = new byte[32];
            RNG.nextBytes(bytes);
            scalars[i] = new BigInteger(1, bytes).mod(FR);
        }
        return scalars;
    }

    private static void assertPointsEqual(JacobianG1BLS381 expected, JacobianG1BLS381 actual) {
        var expAff = expected.toAffine();
        var actAff = actual.toAffine();
        if (expAff.isInfinity() && actAff.isInfinity()) return;
        assertFalse(expAff.isInfinity(), "Expected non-infinity but got infinity");
        assertFalse(actAff.isInfinity(), "Got infinity but expected non-infinity");
        assertEquals(expAff.xBigInt(), actAff.xBigInt(), "X coordinates differ");
        assertEquals(expAff.yBigInt(), actAff.yBigInt(), "Y coordinates differ");
    }
}
