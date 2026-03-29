package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254.AffineG1;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Pippenger MSM algorithm.
 *
 * <p>Cross-validates against naive MSM (individual scalar multiplications summed)
 * for various input sizes and edge cases.</p>
 */
class PippengerTest {

    static final BigInteger FR = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    static final Random RNG = new Random(42);

    // --- Single point ---

    @Test
    void msm_singlePoint() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        BigInteger scalar = BigInteger.valueOf(42);

        var result = Pippenger.msm(new AffineG1[]{g}, new BigInteger[]{scalar});
        var expected = JacobianG1BN254.GENERATOR.scalarMul(scalar);

        assertPointsEqual(expected, result);
    }

    // --- Two points ---

    @Test
    void msm_twoPoints_generator() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        // 3*G + 7*G = 10*G
        var result = Pippenger.msm(
                new AffineG1[]{g, g},
                new BigInteger[]{BigInteger.valueOf(3), BigInteger.valueOf(7)});
        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.TEN);

        assertPointsEqual(expected, result);
    }

    @Test
    void msm_twoDistinctPoints() {
        var g = JacobianG1BN254.GENERATOR;
        var twoG = g.doublePoint();

        // 5*G + 3*(2G) = 5*G + 6*G = 11*G
        var result = Pippenger.msm(
                new AffineG1[]{g.toAffine(), twoG.toAffine()},
                new BigInteger[]{BigInteger.valueOf(5), BigInteger.valueOf(3)});
        var expected = g.scalarMul(BigInteger.valueOf(11));

        assertPointsEqual(expected, result);
    }

    // --- Zero scalars ---

    @Test
    void msm_zeroScalar_skipped() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        // 0*G + 5*G = 5*G
        var result = Pippenger.msm(
                new AffineG1[]{g, g},
                new BigInteger[]{BigInteger.ZERO, BigInteger.valueOf(5)});
        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(5));

        assertPointsEqual(expected, result);
    }

    @Test
    void msm_allZeroScalars() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        var result = Pippenger.msm(
                new AffineG1[]{g, g, g},
                new BigInteger[]{BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO});
        assertTrue(result.isInfinity());
    }

    // --- Empty ---

    @Test
    void msm_empty() {
        assertTrue(Pippenger.msm(new AffineG1[0], new BigInteger[0]).isInfinity());
    }

    // --- Cross-validation against naive MSM ---

    @Test
    void msm_4points_matchesNaive() {
        assertMsmMatchesNaive(4);
    }

    @Test
    void msm_8points_matchesNaive() {
        assertMsmMatchesNaive(8);
    }

    @Test
    void msm_16points_matchesNaive() {
        assertMsmMatchesNaive(16);
    }

    @Test
    void msm_32points_matchesNaive() {
        assertMsmMatchesNaive(32);
    }

    @Test
    void msm_64points_matchesNaive() {
        assertMsmMatchesNaive(64);
    }

    // --- Negative scalars ---

    @Test
    void msm_negativeScalar_matchesNaive() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        // (-5)*G should equal (r-5)*G
        var result = Pippenger.msm(
                new AffineG1[]{g},
                new BigInteger[]{BigInteger.valueOf(-5)});
        var expected = Pippenger.naiveMsm(
                new AffineG1[]{g},
                new BigInteger[]{BigInteger.valueOf(-5)});
        assertPointsEqual(expected, result);
    }

    @Test
    void msm_mixedNegativePositive_matchesNaive() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        var twoG = JacobianG1BN254.GENERATOR.doublePoint().toAffine();
        // (-3)*G + 7*(2G) = -3G + 14G = 11G
        var result = Pippenger.msm(
                new AffineG1[]{g, twoG},
                new BigInteger[]{BigInteger.valueOf(-3), BigInteger.valueOf(7)});
        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(11));
        assertPointsEqual(expected, result);
    }

    @Test
    void msm_allSamePoint_matchesSumOfScalars() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        // 3*G + 7*G + 11*G = 21*G
        var result = Pippenger.msm(
                new AffineG1[]{g, g, g},
                new BigInteger[]{BigInteger.valueOf(3), BigInteger.valueOf(7), BigInteger.valueOf(11)});
        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(21));
        assertPointsEqual(expected, result);
    }

    // --- Large scalars ---

    @Test
    void msm_largeScalars() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        var twoG = JacobianG1BN254.GENERATOR.doublePoint().toAffine();

        BigInteger s1 = new BigInteger("123456789012345678901234567890123456789");
        BigInteger s2 = new BigInteger("987654321098765432109876543210987654321");

        var result = Pippenger.msm(new AffineG1[]{g, twoG}, new BigInteger[]{s1, s2});
        var expected = Pippenger.naiveMsm(new AffineG1[]{g, twoG}, new BigInteger[]{s1, s2});

        assertPointsEqual(expected, result);
    }

    // --- Window size ---

    @Test
    void windowSize_small() {
        assertEquals(3, Pippenger.windowSize(1));
        assertEquals(3, Pippenger.windowSize(4));
        assertEquals(3, Pippenger.windowSize(8));
    }

    @Test
    void windowSize_medium() {
        assertTrue(Pippenger.windowSize(100) >= 3);
        assertTrue(Pippenger.windowSize(1000) >= 3);
        assertTrue(Pippenger.windowSize(1000) <= 16);
    }

    // --- Mismatched lengths ---

    @Test
    void msm_mismatchedLengths_throws() {
        assertThrows(IllegalArgumentException.class, () ->
                Pippenger.msm(
                        new AffineG1[]{JacobianG1BN254.GENERATOR.toAffine()},
                        new BigInteger[]{BigInteger.ONE, BigInteger.TWO}));
    }

    // --- Infinity points ---

    @Test
    void msm_withInfinityPoints() {
        var g = JacobianG1BN254.GENERATOR.toAffine();
        // 5*G + 3*infinity = 5*G
        var result = Pippenger.msm(
                new AffineG1[]{g, AffineG1.INFINITY},
                new BigInteger[]{BigInteger.valueOf(5), BigInteger.valueOf(3)});
        var expected = JacobianG1BN254.GENERATOR.scalarMul(BigInteger.valueOf(5));

        assertPointsEqual(expected, result);
    }

    // --- Result on curve ---

    @Test
    void msm_resultOnCurve() {
        var points = generatePoints(10);
        var scalars = generateScalars(10);
        var result = Pippenger.msm(points, scalars);
        if (!result.isInfinity()) {
            assertTrue(result.toAffine().isOnCurve(), "MSM result must be on curve");
        }
    }

    // --- Helpers ---

    private void assertMsmMatchesNaive(int n) {
        var points = generatePoints(n);
        var scalars = generateScalars(n);

        var pipResult = Pippenger.msm(points, scalars);
        var naiveResult = Pippenger.naiveMsm(points, scalars);

        assertPointsEqual(naiveResult, pipResult);
    }

    private AffineG1[] generatePoints(int n) {
        var points = new AffineG1[n];
        var base = JacobianG1BN254.GENERATOR;
        for (int i = 0; i < n; i++) {
            // Generate distinct points: (i+1)*G
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

    private static void assertPointsEqual(JacobianG1BN254 expected, JacobianG1BN254 actual) {
        var expAff = expected.toAffine();
        var actAff = actual.toAffine();
        if (expAff.isInfinity() && actAff.isInfinity()) return;
        assertFalse(expAff.isInfinity(), "Expected non-infinity but got infinity");
        assertFalse(actAff.isInfinity(), "Expected non-infinity but got infinity");
        assertEquals(expAff.xBigInt(), actAff.xBigInt(), "X coordinates differ");
        assertEquals(expAff.yBigInt(), actAff.yBigInt(), "Y coordinates differ");
    }
}
