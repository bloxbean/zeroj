package org.zeroj.bls12381.ec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.MontFp2_381;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.Bls12381Providers;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 D1 / I1 / I2: the secret ladders run a fixed, blinded operation schedule and return
 * exactly {@code [k mod r]P}.
 *
 * <p>The schedule gate is exact. For every scalar it compares the iterations at which an identity
 * appears (an early-return branch in {@code add}/{@code doublePoint}) with the set predicted by
 * integer arithmetic on the blinded scalar: at iteration {@code i} the inputs are
 * {@code r0 = [a]P}, {@code r1 = [a+1]P} and the sum {@code [2a+1]P}, with
 * {@code a = ⌊k̂ / 2^(i+1)⌋}, so a special case happens iff {@code a}, {@code a+1} or {@code 2a+1}
 * is {@code ≡ 0 (mod r)}.</p>
 *
 * <p>Writing {@code m = q·2^(i+1) + s}, {@code a ≡ ⌊(k + s·r) / 2^(i+1)⌋ (mod r)}, which lies in
 * {@code [0, r)}; it is {@code 0}, {@code r − 1} or {@code (r − 1)/2} only when {@code k} or
 * {@code r − k} is at most {@code 2^(i+1)}. Since {@code m < 2^66}, the predicted set is empty
 * whenever {@code k > 2^66} and {@code r − k > 2^66} ("far" scalars, all but a {@code 2^-188}
 * fraction of {@code [0, r)}); for the remaining "near" scalars it lies in iterations
 * {@code i <= 65} and depends on the low bits of the random {@code m}.</p>
 */
class SecretLadderScheduleTest {
    private static final BigInteger R = G1Point.R;
    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;

    @AfterEach
    void clearObserver() {
        SecretLadder.clearObserverForTesting();
    }

    // ---- I2: fixed operation schedule ----

    @Test
    void everyScalarRunsTheSameScheduleWithNoUnexplainedSpecialCase() {
        Random random = new Random(0x0062_0001L);
        for (BigInteger k : scheduleCorpus()) {
            BigInteger m = SecretLadder.M_MIN.add(new BigInteger(64, random));
            BigInteger kHat = k.add(m.multiply(R));
            Set<Integer> predicted = predictedSpecialIterations(kHat);
            if (isFar(k)) {
                assertEquals(Set.of(), predicted, "far scalar k=" + k.toString(16));
            } else {
                assertTrue(predicted.stream().allMatch(i -> i <= 65), "near scalar k=" + k.toString(16) + " " + predicted);
            }
            Counter g1 = observe(() -> G1.ctScalarMul(k, () -> m));
            g1.assertFixed("G1 k=" + k.toString(16));
            assertEquals(predicted, g1.special, "G1 special iterations, k=" + k.toString(16));
        }
    }

    @Test
    void g2RunsTheSameSchedule() {
        Random random = new Random(0x0062_0002L);
        List<BigInteger> corpus = List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                R.subtract(BigInteger.TWO), R.subtract(BigInteger.ONE), BigInteger.ONE.shiftLeft(200),
                R.subtract(BigInteger.ONE).subtract(BigInteger.ONE.shiftLeft(100)));
        for (BigInteger k : corpus) {
            BigInteger m = SecretLadder.M_MIN.add(new BigInteger(64, random));
            Counter c = observe(() -> G2.ctScalarMul(k, () -> m));
            c.assertFixed("G2 k=" + k.toString(16));
            assertEquals(predictedSpecialIterations(k.add(m.multiply(R))), c.special, "G2 k=" + k.toString(16));
        }
    }

    /** The documented exceptions sit only in the final iterations, never mid-ladder. */
    @Test
    void zeroAndMinusOneAreSpecialOnlyAtTheEnd() {
        for (BigInteger m : List.of(SecretLadder.M_MIN, SecretLadder.M_MAX,
                SecretLadder.M_MIN.add(BigInteger.valueOf(12345)))) {
            for (BigInteger k : List.of(BigInteger.ZERO, R.subtract(BigInteger.ONE))) {
                Set<Integer> predicted = predictedSpecialIterations(k.add(m.multiply(R)));
                assertFalse(predicted.isEmpty());
                // Only the last iterations (i <= 65) can be special for a near scalar.
                assertTrue(predicted.stream().allMatch(i -> i <= 65), "k=" + k + " m=" + m + " " + predicted);
                Counter c = observe(() -> G1.ctScalarMul(k, () -> m));
                c.assertFixed("k=" + k);
                assertEquals(predicted, c.special);
            }
        }
    }

    /** Near scalars: whether an identity appears depends on the random m, not on k alone. */
    @Test
    void nearScalarSpecialCasesDependOnTheBlindingFactor() {
        BigInteger even = SecretLadder.M_MIN; // m ≡ 2 (mod 4): exactly one trailing zero bit
        while (!even.mod(BigInteger.valueOf(4)).equals(BigInteger.TWO)) even = even.add(BigInteger.ONE);
        BigInteger odd = even.add(BigInteger.ONE);
        final BigInteger m2 = even;
        // k = 1: with m even the last prefix is (m·r)/2 ≡ 0 (and, for m ≡ 2 mod 4, the one before
        // is ≡ (r−1)/2); with m odd no prefix is special.
        Set<Integer> evenPredicted = predictedSpecialIterations(BigInteger.ONE.add(even.multiply(R)));
        assertEquals(Set.of(0, 1), evenPredicted);
        assertEquals(Set.of(), predictedSpecialIterations(BigInteger.ONE.add(odd.multiply(R))));
        assertEquals(evenPredicted, observe(() -> G1.ctScalarMul(BigInteger.ONE, () -> m2)).special);
        assertEquals(Set.of(), observe(() -> G1.ctScalarMul(BigInteger.ONE, () -> odd)).special);
        // A far scalar is never special, whatever m is.
        BigInteger far = BigInteger.ONE.shiftLeft(200).add(BigInteger.valueOf(12345));
        for (BigInteger m : List.of(even, odd, SecretLadder.M_MAX, BigInteger.ONE.shiftLeft(65))) {
            assertEquals(Set.of(), predictedSpecialIterations(far.add(m.multiply(R))), "m=" + m);
        }
    }

    private static boolean isFar(BigInteger k) {
        BigInteger bound = BigInteger.ONE.shiftLeft(66);
        return k.compareTo(bound) > 0 && R.subtract(k).compareTo(bound) > 0;
    }

    /** Boundary cases from the M5 review: special iterations can reach i = 65. */
    @Test
    void boundaryNearScalarsReachIteration65() {
        BigInteger k = R.subtract(BigInteger.ONE.shiftLeft(65));
        BigInteger m = new BigInteger("1ffffffffffffffff", 16);
        assertTrue(m.compareTo(SecretLadder.M_MIN) >= 0 && m.compareTo(SecretLadder.M_MAX) <= 0);
        Set<Integer> predicted = predictedSpecialIterations(k.add(m.multiply(R)));
        assertEquals(Set.of(64, 65), predicted);
        Counter c = observe(() -> G1.ctScalarMul(k, () -> m));
        c.assertFixed("r - 2^65");
        assertEquals(predicted, c.special);
        assertEquals(G1.scalarMul(k), G1.ctScalarMul(k, () -> m));

        BigInteger m65 = BigInteger.ONE.shiftLeft(65);
        Set<Integer> zero = predictedSpecialIterations(m65.multiply(R));
        assertTrue(zero.contains(65), zero.toString());
        assertEquals(zero, observe(() -> G1.ctScalarMul(BigInteger.ZERO, () -> m65)).special);
        assertFalse(isFar(k));
    }

    /** Production calls draw a fresh blinding factor each time (a constant m would pass the rest). */
    @Test
    void productionCallsUseFreshBlindingFactors() {
        BigInteger k = BigInteger.valueOf(123456789);
        Counter first = observe(() -> G1.ctScalarMul(k));
        Counter second = observe(() -> G1.ctScalarMul(k));
        Counter viaProvider = observe(() -> Bls12381Providers.pureJava().g2SecretScalarMul(G2, k));
        assertEquals(1, first.factors.size());
        assertEquals(1, second.factors.size());
        assertEquals(1, viaProvider.factors.size());
        assertNotEquals(first.factors.get(0), second.factors.get(0));
        assertNotEquals(first.factors.get(0), viaProvider.factors.get(0));
    }

    @Test
    void candidateMaskAndAcceptanceBoundary() {
        BigInteger range = SecretLadder.M_MAX.subtract(SecretLadder.M_MIN).add(BigInteger.ONE);
        assertEquals(SecretLadder.M_MAX, SecretLadder.candidate(bytes(range.subtract(BigInteger.ONE))));
        assertNull(SecretLadder.candidate(bytes(range)));
        assertEquals(SecretLadder.M_MIN, SecretLadder.candidate(bytes(BigInteger.ZERO)));
        // Bits above the 65-bit candidate width are masked off, not rejected.
        byte[] high = bytes(BigInteger.ONE);
        high[0] |= (byte) 0xfe;
        assertEquals(SecretLadder.M_MIN.add(BigInteger.ONE), SecretLadder.candidate(high));
    }

    @Test
    void aThrowingSecureRandomPropagates() {
        SecureRandom broken = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                throw new IllegalStateException("entropy source failed");
            }
        };
        assertThrows(IllegalStateException.class, () -> SecretLadder.sample(broken));
    }

    @Test
    void jacobianLaddersRejectBadInputs() {
        G2Point torsion = g2PointOutsideSubgroup();
        var g2Jac = JacobianG2BLS381.fromAffine(
                MontFp2_381.of(torsion.x().c0().value(), torsion.x().c1().value()),
                MontFp2_381.of(torsion.y().c0().value(), torsion.y().c1().value()));
        assertThrows(IllegalArgumentException.class, () -> g2Jac.ctScalarMul(BigInteger.TWO));
        // (4x, 8y) lies on the isomorphic curve y^2 = x^3 + 256, which has r-torsion: the subgroup
        // check alone would accept it, the on-curve check rejects it.
        var g = JacobianG1BLS381.GENERATOR.toAffine();
        var iso = JacobianG1BLS381.fromAffine(g.xBigInt().multiply(BigInteger.valueOf(4)).mod(Fp.P),
                g.yBigInt().multiply(BigInteger.valueOf(8)).mod(Fp.P));
        assertTrue(iso.scalarMul(R).isInfinity(), "the isomorphic point has order r");
        assertThrows(IllegalArgumentException.class, () -> iso.ctScalarMul(BigInteger.TWO));
        assertThrows(NullPointerException.class, () -> JacobianG1BLS381.GENERATOR.ctScalarMul(null));
        assertThrows(NullPointerException.class, () -> G1.ctScalarMul(null));
    }

    private static byte[] bytes(BigInteger u) {
        byte[] out = new byte[SecretLadder.CANDIDATE_BYTES];
        byte[] be = u.toByteArray();
        int n = Math.min(be.length, out.length);
        System.arraycopy(be, be.length - n, out, out.length - n, n);
        return out;
    }

    // ---- I1: output identity ----

    @Test
    void outputEqualsPublicScalarMulForEveryCorpusScalar() {
        Random random = new Random(0x0062_0003L);
        for (BigInteger k : scheduleCorpus()) {
            BigInteger m = SecretLadder.M_MIN.add(new BigInteger(64, random));
            assertEquals(G1.scalarMul(k.mod(R)), G1.ctScalarMul(k, () -> m), "k=" + k.toString(16));
        }
        for (int i = 0; i < 16; i++) {
            BigInteger k = new BigInteger(256, random);
            assertEquals(G1.scalarMul(k.mod(R)), G1.ctScalarMul(k), "G1 random " + i);
            assertEquals(G2.scalarMul(k.mod(R)), G2.ctScalarMul(k), "G2 random " + i);
        }
    }

    @Test
    void differentBlindingFactorsGiveTheSameOutput() {
        BigInteger k = new BigInteger("5a1f0e9d8c7b6a5948372615f4e3d2c1b0a9f8e7d6c5b4a3928170f6e5d4c3b", 16).mod(R);
        G1Point expected = G1.scalarMul(k);
        for (BigInteger m : List.of(SecretLadder.M_MIN, SecretLadder.M_MAX,
                SecretLadder.M_MIN.add(BigInteger.ONE.shiftLeft(63)))) {
            assertEquals(expected, G1.ctScalarMul(k, () -> m), "m=" + m);
            assertEquals(G2.scalarMul(k), G2.ctScalarMul(k, () -> m), "m=" + m);
        }
    }

    @Test
    void negativeAndOversizedScalarsAreReducedModR() {
        for (BigInteger k : List.of(BigInteger.valueOf(-1), R, R.add(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(255).add(BigInteger.ONE), BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE))) {
            assertEquals(G1.scalarMul(k.mod(R)), G1.ctScalarMul(k), "k=" + k);
        }
        assertTrue(G1.ctScalarMul(BigInteger.ZERO).isInfinity());
        assertTrue(G1.ctScalarMul(R).isInfinity());
        assertThrows(IllegalArgumentException.class, () -> G1.ctScalarMul(BigInteger.ONE.shiftLeft(256)));
    }

    // ---- fail closed ----

    /** [k + m·r]P = [k]P only inside the prime-order subgroup, so other points must be rejected. */
    @Test
    void pointsOutsideTheSubgroupAreRejected() {
        G1Point g1Torsion = g1PointOutsideSubgroup();
        G2Point g2Torsion = g2PointOutsideSubgroup();
        assertThrows(IllegalArgumentException.class, () -> g1Torsion.ctScalarMul(BigInteger.TWO));
        assertThrows(IllegalArgumentException.class, () -> g2Torsion.ctScalarMul(BigInteger.TWO));
        assertThrows(IllegalArgumentException.class,
                () -> JacobianG1BLS381.fromAffine(g1Torsion.x().value(), g1Torsion.y().value()).ctScalarMul(BigInteger.TWO));
        Bls12381Provider pure = Bls12381Providers.pureJava();
        assertThrows(IllegalArgumentException.class, () -> pure.g1SecretScalarMul(g1Torsion, BigInteger.TWO));
        assertThrows(IllegalArgumentException.class, () -> pure.g2SecretScalarMul(g2Torsion, BigInteger.TWO));
        G1Point offCurve = new G1Point(Fp.ONE, Fp.ONE);
        assertThrows(IllegalArgumentException.class, () -> offCurve.ctScalarMul(BigInteger.TWO));
    }

    @Test
    void aFailingRandomSourcePropagatesWithNoUnblindedFallback() {
        IllegalStateException failure = new IllegalStateException("entropy unavailable");
        SecretLadder.BlindingSource broken = () -> { throw failure; };
        assertSame(failure, assertThrows(IllegalStateException.class, () -> G1.ctScalarMul(BigInteger.TEN, broken)));
        assertSame(failure, assertThrows(IllegalStateException.class, () -> G2.ctScalarMul(BigInteger.TEN, broken)));
    }

    @Test
    void blindingFactorsOutsideTheRangeAreRejected() {
        BigInteger below = SecretLadder.M_MIN.subtract(BigInteger.ONE);
        BigInteger above = SecretLadder.M_MAX.add(BigInteger.ONE);
        assertThrows(IllegalStateException.class, () -> G1.ctScalarMul(BigInteger.TEN, () -> below));
        assertThrows(IllegalStateException.class, () -> G1.ctScalarMul(BigInteger.TEN, () -> above));
        assertThrows(NullPointerException.class, () -> G1.ctScalarMul(BigInteger.TEN, () -> null));
    }

    // ---- the blinding range ----

    @Test
    void rangeEndsGiveExactly320BitsForEveryReducedScalar() {
        assertEquals(BigInteger.ONE.shiftLeft(319).add(R).subtract(BigInteger.ONE).divide(R), SecretLadder.M_MIN);
        assertEquals(BigInteger.ONE.shiftLeft(320).subtract(R).divide(R), SecretLadder.M_MAX);
        for (BigInteger m : List.of(SecretLadder.M_MIN, SecretLadder.M_MAX)) {
            for (BigInteger k : List.of(BigInteger.ZERO, R.subtract(BigInteger.ONE))) {
                assertEquals(320, SecretLadder.blind(k, () -> m).bitLength(), "m=" + m + " k=" + k);
            }
        }
        // Just outside the range, some reduced scalar leaves the 320-bit window.
        assertTrue(SecretLadder.M_MIN.subtract(BigInteger.ONE).multiply(R).bitLength() < 320);
        assertTrue(SecretLadder.M_MAX.add(BigInteger.ONE).multiply(R).add(R.subtract(BigInteger.ONE)).bitLength() > 320);
        // About 2^64 values: each call takes about 64 bits of entropy.
        assertEquals(65, SecretLadder.M_MAX.subtract(SecretLadder.M_MIN).add(BigInteger.ONE).bitLength());
    }

    @Test
    void secureSamplesStayInRange() {
        SecureRandom random = new SecureRandom();
        Set<BigInteger> seen = new LinkedHashSet<>();
        for (int i = 0; i < 2000; i++) {
            BigInteger m = SecretLadder.sample(random);
            assertTrue(m.compareTo(SecretLadder.M_MIN) >= 0 && m.compareTo(SecretLadder.M_MAX) <= 0, m.toString());
            seen.add(m);
        }
        assertTrue(seen.size() > 1990, "fresh blinding factors repeat: " + seen.size());
    }

    // ---- production call sites use the blinded schedule ----

    @Test
    void providerAndPedersenGenerationUseTheBlindedSchedule() {
        Bls12381Provider pure = Bls12381Providers.pureJava();
        Counter secret = observe(() -> pure.g1SecretScalarMul(G1, BigInteger.ONE));
        secret.assertFixed("provider g1");
        assertEquals(List.of(SecretLadder.ITERATIONS), secret.schedules);
        Counter secret2 = observe(() -> pure.g2SecretScalarMul(G2, BigInteger.ZERO));
        assertEquals(List.of(SecretLadder.ITERATIONS), secret2.schedules);
        Counter publicMul = observe(() -> pure.g1ScalarMul(G1, BigInteger.TEN));
        assertEquals(List.of(), publicMul.schedules, "the public path must not run the secret ladder");

        G1Pedersen pedersenInstance = G1Pedersen.pureJava(); // its capability probe runs here
        Counter pedersen = observe(() -> pedersenInstance.commitScalar(BigInteger.valueOf(42), BigInteger.valueOf(7)));
        assertEquals(List.of(SecretLadder.ITERATIONS, SecretLadder.ITERATIONS), pedersen.schedules,
                "commit = [m]G + [r]H runs two blinded ladders");
    }

    // ---- helpers ----

    /** 0, 1, 2, r−2, r−1, every bit length 1..255, low and high Hamming weight. */
    private static List<BigInteger> scheduleCorpus() {
        List<BigInteger> corpus = new ArrayList<>(List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                R.subtract(BigInteger.TWO), R.subtract(BigInteger.ONE)));
        Random random = new Random(0x0062_0004L);
        for (int bits = 1; bits <= 255; bits++) {
            BigInteger low = BigInteger.ONE.shiftLeft(bits - 1);                  // Hamming weight 1
            BigInteger high = BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE); // all ones
            BigInteger mixed = low.or(new BigInteger(bits - 1, random));
            for (BigInteger k : List.of(low, high, mixed)) {
                if (k.compareTo(R) < 0) corpus.add(k);
            }
        }
        return corpus;
    }

    private static Set<Integer> predictedSpecialIterations(BigInteger kHat) {
        Set<Integer> out = new TreeSet<>();
        for (int i = SecretLadder.WIDTH - 2; i >= 0; i--) {
            BigInteger a = kHat.shiftRight(i + 1);
            if (a.mod(R).signum() == 0 || a.add(BigInteger.ONE).mod(R).signum() == 0
                    || a.shiftLeft(1).add(BigInteger.ONE).mod(R).signum() == 0) {
                out.add(i);
            }
        }
        return out;
    }

    private static Counter observe(Supplier<?> operation) {
        Counter counter = new Counter();
        SecretLadder.installObserverForTesting(counter);
        try {
            operation.get();
        } finally {
            SecretLadder.clearObserverForTesting();
        }
        return counter;
    }

    private static final class Counter implements SecretLadder.ScheduleObserver {
        final List<Integer> schedules = new ArrayList<>();
        final Set<Integer> special = new TreeSet<>();
        final List<BigInteger> factors = new ArrayList<>();
        int additions;
        int doublings;

        @Override public void scheduleStarted(int iterations) { schedules.add(iterations); }
        @Override public void addition() { additions++; }
        @Override public void doubling() { doublings++; }
        @Override public void specialCase(int bitIndex) { special.add(bitIndex); }
        @Override public void blindingFactor(BigInteger m) { factors.add(m); }

        void assertFixed(String label) {
            assertEquals(List.of(SecretLadder.ITERATIONS), schedules, label);
            assertEquals(SecretLadder.ITERATIONS, additions, label);
            assertEquals(SecretLadder.ITERATIONS, doublings, label);
        }
    }

    private static G1Point g1PointOutsideSubgroup() {
        for (int x = 1; ; x++) {
            Fp fx = Fp.of(x);
            var y = fx.square().mul(fx).add(Fp.of(4)).sqrt();
            if (y.isPresent() && !new G1Point(fx, y.get()).isInSubgroup()) return new G1Point(fx, y.get());
        }
    }

    private static G2Point g2PointOutsideSubgroup() {
        for (int x = 1; ; x++) {
            Fp2 fx = Fp2.of(Fp.of(x), Fp.ZERO);
            var y = fx.square().mul(fx).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt();
            if (y.isPresent() && !new G2Point(fx, y.get()).isInSubgroup()) return new G2Point(fx, y.get());
        }
    }
}
