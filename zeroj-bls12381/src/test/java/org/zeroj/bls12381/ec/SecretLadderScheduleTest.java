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
 * ADR-0062 D1 (r4) / I1 / I2: the secret ladders split the scalar into two fresh uniform shares
 * (Clavier–Joye, CHES 2001), run a fixed schedule on each recoded share, and return exactly
 * {@code [k mod r]P}.
 *
 * <p>The schedule gate is exact. For each ladder it compares the iterations at which an identity
 * appears (an early-return branch in {@code add}/{@code doublePoint}) with the set predicted by
 * integer arithmetic on the recoded share: at iteration {@code i} the inputs are {@code [a]P},
 * {@code [a+1]P} and the sum {@code [2a+1]P}, with {@code a = ⌊ŝ / 2^(i+1)⌋}, so a special case
 * happens iff {@code a}, {@code a+1} or {@code 2a+1} is {@code ≡ 0 (mod r)}.</p>
 */
class SecretLadderScheduleTest {
    private static final BigInteger R = G1Point.R;
    private static final G1Point G1 = Bls12381Generators.G1;
    private static final G2Point G2 = Bls12381Generators.G2;

    /** The scalars the maintainer's F12 simulation showed leaking through the r1–r3 blinded ladder. */
    private static final List<BigInteger> LOW_ENTROPY = List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
            BigInteger.valueOf(5), BigInteger.ONE.shiftLeft(64), R.subtract(BigInteger.TWO), R.subtract(BigInteger.ONE));

    @AfterEach
    void clearObserver() {
        SecretLadder.clearObserverForTesting();
    }

    // ---- I2: fixed operation schedule, no identity steps for any secret ----

    /**
     * Requirement 4 (ADR-0062 r4): for low-entropy and random secrets, over many seeds, neither ladder
     * takes a special step; the only allowed exception is the final addition for {@code k = 0}.
     */
    @Test
    void lowEntropySecretsTakeNoSpecialStepInEitherLadder() {
        Random random = new Random(0x0062_0401L);
        List<BigInteger> scalars = new ArrayList<>(LOW_ENTROPY);
        scalars.add(new BigInteger(255, random).mod(R));
        for (BigInteger k : scalars) {
            for (int seed = 0; seed < 64; seed++) {
                BigInteger k1 = new BigInteger(255, random).mod(R);
                Counter c = observe(() -> G1.ctScalarMul(k, () -> k1));
                c.assertFixed("k=" + k.toString(16));
                assertEquals(List.of(Set.of(), Set.of()), c.special, "k=" + k.toString(16) + " k1=" + k1.toString(16));
                assertEquals(k.signum() == 0, c.combinationSpecial, "combination k=" + k.toString(16));
            }
        }
    }

    @Test
    void g2RunsTheSameScheduleWithNoSpecialStep() {
        Random random = new Random(0x0062_0402L);
        for (BigInteger k : LOW_ENTROPY) {
            BigInteger k1 = new BigInteger(255, random).mod(R);
            Counter c = observe(() -> G2.ctScalarMul(k, () -> k1));
            c.assertFixed("G2 k=" + k.toString(16));
            assertEquals(List.of(Set.of(), Set.of()), c.special, "G2 k=" + k.toString(16));
            assertEquals(k.signum() == 0, c.combinationSpecial);
        }
    }

    /** The instrumentation matches the arithmetic model, including the probability-1/r share cases. */
    @Test
    void observedSpecialStepsEqualThePrediction() {
        BigInteger k = BigInteger.valueOf(1234567);
        // k1 = 0 and k1 = k (so k2 = 0): the corresponding ladder ends at the identity.
        for (BigInteger k1 : List.of(BigInteger.ZERO, k)) {
            BigInteger k2 = k.subtract(k1).mod(R);
            Counter c = observe(() -> G1.ctScalarMul(k, () -> k1));
            c.assertFixed("k1=" + k1);
            assertEquals(List.of(predicted(SecretLadder.recode(k1)), predicted(SecretLadder.recode(k2))), c.special);
            assertTrue(c.combinationSpecial, "an identity operand in the final addition");
            assertFalse(c.special.get(0).isEmpty() && c.special.get(1).isEmpty());
        }
        // k1 = k2 (k = 2·k1): the final addition is a doubling.
        BigInteger half = BigInteger.valueOf(777);
        Counter c = observe(() -> G1.ctScalarMul(half.shiftLeft(1), () -> half));
        assertEquals(List.of(Set.of(), Set.of()), c.special);
        assertTrue(c.combinationSpecial);
        assertEquals(G1.scalarMul(half.shiftLeft(1)), G1.ctScalarMul(half.shiftLeft(1), () -> half));
    }

    /**
     * Why r4 replaced the blinding (ADR-0062 F12): with {@code k̂ = k + m·r}, {@code m} uniform in the
     * 64-bit window, the prefix at step {@code i} is {@code ⌊k/2^i⌋ mod r} whenever {@code 2^i | m},
     * which is 0 for small {@code k}. Same model, 400 runs per scalar: the blinded construction hits
     * identity steps for every low-entropy scalar, the split hits none.
     */
    @Test
    void blindingAloneLeakedAndTheSplitDoesNot() {
        BigInteger mMin = BigInteger.ONE.shiftLeft(319).add(R).subtract(BigInteger.ONE).divide(R);
        BigInteger mRange = BigInteger.ONE.shiftLeft(320).subtract(R).divide(R).subtract(mMin).add(BigInteger.ONE);
        Random random = new Random(0x0062_0403L);
        int[] blindedHits = new int[LOW_ENTROPY.size()];
        int[] splitHits = new int[LOW_ENTROPY.size()];
        for (int run = 0; run < 400; run++) {
            for (int j = 0; j < LOW_ENTROPY.size(); j++) {
                BigInteger k = LOW_ENTROPY.get(j);
                BigInteger m = mMin.add(new BigInteger(66, random).mod(mRange));
                if (!predicted(k.add(m.multiply(R)), 320).isEmpty()) blindedHits[j]++;
                BigInteger k1 = new BigInteger(255, random).mod(R);
                BigInteger k2 = k.subtract(k1).mod(R);
                if (!predicted(SecretLadder.recode(k1)).isEmpty() || !predicted(SecretLadder.recode(k2)).isEmpty()) {
                    splitHits[j]++;
                }
            }
        }
        assertEquals(400, blindedHits[0], "k = 0");
        assertEquals(400, blindedHits[6], "k = r - 1");
        assertTrue(blindedHits[1] > 150 && blindedHits[1] < 250, "k = 1: about half, got " + blindedHits[1]);
        for (int j = 0; j < LOW_ENTROPY.size(); j++) {
            if (j != 4) assertTrue(blindedHits[j] > 0, "blinded k=" + LOW_ENTROPY.get(j));
            assertEquals(0, splitHits[j], "split k=" + LOW_ENTROPY.get(j));
        }
    }

    // ---- recoding ----

    @Test
    void recodingGives256BitsAndPreservesTheResidue() {
        BigInteger top = BigInteger.ONE.shiftLeft(255);
        for (BigInteger s : List.of(BigInteger.ZERO, BigInteger.ONE, R.subtract(BigInteger.ONE),
                top.subtract(R).subtract(BigInteger.ONE), top.subtract(R), top.subtract(R).add(BigInteger.ONE))) {
            BigInteger hat = SecretLadder.recode(s.mod(R));
            assertEquals(256, hat.bitLength(), "s=" + s);
            assertEquals(s.mod(R), hat.mod(R), "s=" + s);
        }
    }

    // ---- I1: output identity ----

    @Test
    void outputEqualsPublicScalarMul() {
        Random random = new Random(0x0062_0404L);
        for (BigInteger k : LOW_ENTROPY) {
            BigInteger k1 = new BigInteger(255, random).mod(R);
            assertEquals(G1.scalarMul(k), G1.ctScalarMul(k, () -> k1), "k=" + k.toString(16));
        }
        for (int i = 0; i < 16; i++) {
            BigInteger k = new BigInteger(256, random);
            assertEquals(G1.scalarMul(k.mod(R)), G1.ctScalarMul(k), "G1 random " + i);
            assertEquals(G2.scalarMul(k.mod(R)), G2.ctScalarMul(k), "G2 random " + i);
        }
    }

    @Test
    void differentSharesGiveTheSameOutput() {
        BigInteger k = new BigInteger("5a1f0e9d8c7b6a5948372615f4e3d2c1b0a9f8e7d6c5b4a3928170f6e5d4c3b", 16).mod(R);
        for (BigInteger k1 : List.of(BigInteger.ZERO, BigInteger.ONE, k, R.subtract(BigInteger.ONE))) {
            assertEquals(G1.scalarMul(k), G1.ctScalarMul(k, () -> k1), "k1=" + k1);
            assertEquals(G2.scalarMul(k), G2.ctScalarMul(k, () -> k1), "k1=" + k1);
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

    /** [ŝ]P = [s]P only inside the prime-order subgroup, so other points must be rejected. */
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

    @Test
    void aFailingRandomSourcePropagatesWithNoUnsplitFallback() {
        IllegalStateException failure = new IllegalStateException("entropy unavailable");
        SecretLadder.ShareSource broken = () -> { throw failure; };
        assertSame(failure, assertThrows(IllegalStateException.class, () -> G1.ctScalarMul(BigInteger.TEN, broken)));
        assertSame(failure, assertThrows(IllegalStateException.class, () -> G2.ctScalarMul(BigInteger.TEN, broken)));
        SecureRandom brokenRandom = new SecureRandom() {
            @Override
            public void nextBytes(byte[] bytes) {
                throw new IllegalStateException("entropy source failed");
            }
        };
        assertThrows(IllegalStateException.class, () -> SecretLadder.sample(brokenRandom));
    }

    @Test
    void sharesOutsideTheRangeAreRejected() {
        assertThrows(IllegalStateException.class, () -> G1.ctScalarMul(BigInteger.TEN, () -> BigInteger.valueOf(-1)));
        assertThrows(IllegalStateException.class, () -> G1.ctScalarMul(BigInteger.TEN, () -> R));
        assertThrows(NullPointerException.class, () -> G1.ctScalarMul(BigInteger.TEN, () -> null));
    }

    // ---- share sampling ----

    @Test
    void candidateMaskAndAcceptanceBoundary() {
        assertEquals(R.subtract(BigInteger.ONE), SecretLadder.candidate(bytes(R.subtract(BigInteger.ONE))));
        assertNull(SecretLadder.candidate(bytes(R)));
        assertEquals(BigInteger.ZERO, SecretLadder.candidate(bytes(BigInteger.ZERO)));
        // The top bit is masked off (255-bit candidates), not rejected.
        byte[] high = bytes(BigInteger.ONE);
        high[0] |= (byte) 0x80;
        assertEquals(BigInteger.ONE, SecretLadder.candidate(high));
    }

    @Test
    void secureSharesStayInRangeAndDoNotRepeat() {
        SecureRandom random = new SecureRandom();
        Set<BigInteger> seen = new LinkedHashSet<>();
        for (int i = 0; i < 2000; i++) {
            BigInteger k1 = SecretLadder.sample(random);
            assertTrue(k1.signum() >= 0 && k1.compareTo(R) < 0, k1.toString());
            seen.add(k1);
        }
        assertEquals(2000, seen.size());
    }

    /** Production calls draw a fresh share each time (a constant share would pass the rest). */
    @Test
    void productionCallsUseFreshShares() {
        BigInteger k = BigInteger.valueOf(123456789);
        Counter first = observe(() -> G1.ctScalarMul(k));
        Counter second = observe(() -> G1.ctScalarMul(k));
        Counter viaProvider = observe(() -> Bls12381Providers.pureJava().g2SecretScalarMul(G2, k));
        assertEquals(1, first.shares.size());
        assertEquals(1, second.shares.size());
        assertEquals(1, viaProvider.shares.size());
        assertNotEquals(first.shares.get(0), second.shares.get(0));
        assertNotEquals(first.shares.get(0), viaProvider.shares.get(0));
    }

    // ---- production call sites ----

    @Test
    void providerAndPedersenGenerationUseTheSplitSchedule() {
        Bls12381Provider pure = Bls12381Providers.pureJava();
        Counter secret = observe(() -> pure.g1SecretScalarMul(G1, BigInteger.ONE));
        secret.assertFixed("provider g1");
        Counter secret2 = observe(() -> pure.g2SecretScalarMul(G2, BigInteger.ZERO));
        secret2.assertFixed("provider g2");
        Counter publicMul = observe(() -> pure.g1ScalarMul(G1, BigInteger.TEN));
        assertEquals(List.of(), publicMul.schedules, "the public path must not run the secret ladder");

        G1Pedersen pedersen = G1Pedersen.pureJava(); // its capability probe runs here
        for (BigInteger value : List.of(BigInteger.ZERO, BigInteger.ONE)) {
            Counter c = observe(() -> pedersen.commitScalar(value, BigInteger.valueOf(7)));
            assertEquals(6, c.schedules.size(), "commit = [x−t]G + [r]H + [t]G: three split multiplications");
            assertTrue(c.special.stream().allMatch(Set::isEmpty), "value " + value);
            assertFalse(c.combinationSpecial, "value " + value);
        }
    }

    // ---- helpers ----

    /** Special iterations of a ladder over a 256-bit recoded share. */
    private static Set<Integer> predicted(BigInteger hat) {
        return predicted(hat, SecretLadder.WIDTH);
    }

    private static Set<Integer> predicted(BigInteger hat, int width) {
        Set<Integer> out = new TreeSet<>();
        for (int i = width - 2; i >= 0; i--) {
            BigInteger a = hat.shiftRight(i + 1);
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
        final List<Set<Integer>> special = new ArrayList<>();
        final List<BigInteger> shares = new ArrayList<>();
        boolean combinationSpecial;
        int additions;
        int doublings;

        @Override public void scheduleStarted(int iterations) { schedules.add(iterations); special.add(new TreeSet<>()); }
        @Override public void addition() { additions++; }
        @Override public void doubling() { doublings++; }
        @Override public void specialCase(int bitIndex) { special.get(special.size() - 1).add(bitIndex); }
        @Override public void combinationSpecial() { combinationSpecial = true; }
        @Override public void share(BigInteger k1) { shares.add(k1); }

        /** One split multiplication: two ladders of 255 iterations, one addition and doubling each. */
        void assertFixed(String label) {
            assertEquals(List.of(SecretLadder.ITERATIONS, SecretLadder.ITERATIONS), schedules, label);
            assertEquals(2 * SecretLadder.ITERATIONS, additions, label);
            assertEquals(2 * SecretLadder.ITERATIONS, doublings, label);
        }
    }

    private static byte[] bytes(BigInteger u) {
        byte[] out = new byte[SecretLadder.CANDIDATE_BYTES];
        byte[] be = u.toByteArray();
        int n = Math.min(be.length, out.length);
        System.arraycopy(be, be.length - n, out, out.length - n, n);
        return out;
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
