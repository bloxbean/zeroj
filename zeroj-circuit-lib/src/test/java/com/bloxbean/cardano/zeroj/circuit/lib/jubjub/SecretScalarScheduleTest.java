package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.lang.reflect.Modifier;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0038 Decision 4 / phase P4: secret scalar multiplication runs a fixed schedule.
 *
 * <p>The operation-count gate here is deterministic and belongs in CI. The timing correlation
 * it is a proxy for is <b>not</b> asserted anywhere — that is a separately recorded statistical
 * benchmark, because a timing assertion in a unit test is flaky, and because a timing harness
 * that fails to find a leak does not establish that there is none.
 *
 * <p>Scope, restated so a green suite is not mistaken for more than it is: this removes the
 * loop-bound and operation-count channel. Signing is still <b>not</b> constant-time and remains
 * offline-only.
 */
class SecretScalarScheduleTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    // ------------------------------------------------------------------
    //  Correctness first: the schedule change must not change any result
    // ------------------------------------------------------------------

    @Test
    void fixedScheduleAgreesWithVariableLengthPath() {
        for (BigInteger k : interestingScalars()) {
            assertEquals(G.scalarMul(k), G.scalarMulSecretRaw252UnsafeForTiming(k),
                    "fixed and variable paths disagree at k = " + k);
        }
    }

    @Test
    void fixedScheduleAgreesOnRandomScalars() {
        var rng = new Random(0x01020304L);   // deterministic corpus for reproducible failures
        for (int i = 0; i < 32; i++) {
            BigInteger k = new BigInteger(L.bitLength(), rng).mod(L);
            assertEquals(G.scalarMul(k), G.scalarMulSecretRaw252UnsafeForTiming(k), "k = " + k);
        }
    }

    @Test
    void blindedScheduleAgreesForKnownSubgroupBases() {
        BigInteger maxBlind = BigInteger.ONE
                .shiftLeft(JubjubPoint.SECRET_SCALAR_BLINDING_BITS)
                .subtract(BigInteger.ONE);
        for (BigInteger k : interestingScalars()) {
            JubjubPoint expectedG = G.scalarMul(k);
            JubjubPoint expectedH = PedersenCommitment.H.scalarMul(k);
            for (BigInteger m : new BigInteger[]{
                    BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(0x5eed), maxBlind}) {
                assertEquals(expectedG, G.scalarMulSecretBlindedBestEffort(k, m),
                        "G mismatch at k=" + k + ", m=" + m);
                assertEquals(expectedH,
                        PedersenCommitment.H.scalarMulSecretBlindedBestEffort(k, m),
                        "H mismatch at k=" + k + ", m=" + m);
            }
        }
    }

    @Test
    void blindedScheduleEnforcesScalarAndBlindingRanges() {
        BigInteger blindLimit =
                BigInteger.ONE.shiftLeft(JubjubPoint.SECRET_SCALAR_BLINDING_BITS);
        assertThrows(IllegalArgumentException.class,
                () -> G.scalarMulSecretBlindedBestEffort(BigInteger.valueOf(-1), BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> G.scalarMulSecretBlindedBestEffort(L, BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> G.scalarMulSecretBlindedBestEffort(BigInteger.ONE, BigInteger.valueOf(-1)));
        assertThrows(IllegalArgumentException.class,
                () -> G.scalarMulSecretBlindedBestEffort(BigInteger.ONE, blindLimit));
        assertDoesNotThrow(() -> G.scalarMulSecretBlindedBestEffort(
                L.subtract(BigInteger.ONE), blindLimit.subtract(BigInteger.ONE)));
    }

    /**
     * Multiple-of-l blinding is valid only for a point whose order divides l. Keep this
     * counterexample load-bearing so the package-private helper is never widened into a general
     * JubjubPoint API without a subgroup precondition.
     */
    @Test
    void scalarBlindingWouldChangeAMixedOrderPoint() {
        BigInteger k = BigInteger.valueOf(7);
        assertNotEquals(JubjubPoint.FULL_GENERATOR.scalarMul(k),
                JubjubPoint.FULL_GENERATOR.scalarMulSecretBlindedBestEffort(k, BigInteger.ONE));
    }

    @Test
    void debugModeRejectsScalarBlindingOnAMixedOrderBase() {
        String property = JubjubPoint.DEBUG_SECRET_SUBGROUP_PROPERTY;
        String previous = System.getProperty(property);
        System.setProperty(property, "true");
        try {
            assertThrows(IllegalStateException.class,
                    () -> JubjubPoint.FULL_GENERATOR.scalarMulSecretBlindedBestEffort(
                            BigInteger.ONE, BigInteger.ONE));
            assertDoesNotThrow(() -> G.scalarMulSecretBlindedBestEffort(
                    BigInteger.ONE, BigInteger.ONE));
        } finally {
            if (previous == null) {
                System.clearProperty(property);
            } else {
                System.setProperty(property, previous);
            }
        }
    }

    @Test
    void zeroScalarYieldsIdentity() {
        assertTrue(G.scalarMulSecretRaw252UnsafeForTiming(BigInteger.ZERO).isIdentity(),
                "[0]·G must still be the identity — the early exit is removed, not the result");
    }

    @Test
    void rangeIsEnforced() {
        assertThrows(IllegalArgumentException.class,
                () -> G.scalarMulSecretRaw252UnsafeForTiming(BigInteger.valueOf(-1)));
        assertThrows(IllegalArgumentException.class, () -> G.scalarMulSecretRaw252UnsafeForTiming(L));
        assertThrows(IllegalArgumentException.class,
                () -> G.scalarMulSecretRaw252UnsafeForTiming(L.add(BigInteger.ONE)));
        assertDoesNotThrow(() -> G.scalarMulSecretRaw252UnsafeForTiming(L.subtract(BigInteger.ONE)));
        assertDoesNotThrow(() -> G.scalarMulSecretRaw252UnsafeForTiming(BigInteger.ZERO));
    }

    @Test
    void rawFixedPrimitiveIsNotPublicApi() throws NoSuchMethodException {
        var method = JubjubPoint.class.getDeclaredMethod(
                "scalarMulSecretRaw252UnsafeForTiming", BigInteger.class);
        assertFalse(Modifier.isPublic(method.getModifiers()),
                "the unblinded low-bit timing primitive must remain package-private");
    }

    // ------------------------------------------------------------------
    //  The operation-count gate
    // ------------------------------------------------------------------

    /**
     * Identical add and double counts for every scalar in range, whatever its bit length or
     * Hamming weight — including {@code 0} and {@code l − 1}, the two boundaries ADR-0038
     * calls out. The observer is invoked by the production loop itself; this test does not
     * duplicate or paraphrase that loop.
     */
    @Test
    void addAndDoubleCountsAreIdenticalAcrossAllScalars() {
        Counter reference = count(BigInteger.ONE);

        assertEquals(JubjubCurve.SCALAR_BITS, reference.adds,
                "one addition per iteration, never skipped");
        assertEquals(JubjubCurve.SCALAR_BITS, reference.doubles,
                "one doubling per iteration");

        for (BigInteger k : interestingScalars()) {
            Counter c = count(k);
            assertEquals(reference.adds, c.adds,
                    "addition count varies with the scalar at k = " + k
                            + " (bitLength " + k.bitLength() + ", weight " + k.bitCount() + ")");
            assertEquals(reference.doubles, c.doubles,
                    "doubling count varies with the scalar at k = " + k);
        }
    }

    /** The two boundaries, named explicitly so a regression cannot quietly drop them. */
    @Test
    void zeroAndLMinusOneRunTheIdenticalSchedule() {
        Counter zero = count(BigInteger.ZERO);
        Counter max = count(L.subtract(BigInteger.ONE));

        assertEquals(JubjubCurve.SCALAR_BITS, zero.adds);
        assertEquals(JubjubCurve.SCALAR_BITS, zero.doubles);
        assertEquals(zero.adds, max.adds);
        assertEquals(zero.doubles, max.doubles);
    }

    @Test
    void blindedZeroAndBoundaryRunTheIdentical316OperationSchedule() {
        Counter zero = countBlinded(BigInteger.ZERO, BigInteger.valueOf(7));
        Counter max = countBlinded(L.subtract(BigInteger.ONE),
                BigInteger.ONE.shiftLeft(JubjubPoint.SECRET_SCALAR_BLINDING_BITS)
                        .subtract(BigInteger.ONE));

        assertEquals(JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS, zero.adds);
        assertEquals(JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS, zero.doubles);
        assertEquals(zero.adds, max.adds);
        assertEquals(zero.doubles, max.doubles);
    }

    @Test
    void productionSecretCallSitesUseTheBlindedSchedule() {
        BigInteger sk = BigInteger.valueOf(0x5eed);
        BigInteger msg = EdDSAJubjub.hashToField("production schedule".getBytes());
        var keypair = EdDSAJubjub.keypairFromSecret(sk);

        Counter keygen = observe(() -> EdDSAJubjub.keypairFromSecret(sk));
        assertSchedules(keygen, 1);

        Counter sign = observe(() -> EdDSAJubjub.sign(keypair, msg));
        assertSchedules(sign, 1);

        @SuppressWarnings("deprecation")
        Counter deprecatedSign = observe(() -> EdDSAJubjub.sign(sk, msg));
        assertSchedules(deprecatedSign, 2);

        Counter commit = observe(() -> PedersenCommitment.commit(
                BigInteger.valueOf(42), BigInteger.valueOf(12345)));
        assertSchedules(commit, 2);
    }

    // ------------------------------------------------------------------
    //  Golden vectors must be bit-identical: an execution change, not a scheme change
    // ------------------------------------------------------------------

    @Test
    void signatureIsUnchangedByTheScheduleChange() {
        BigInteger sk = BigInteger.valueOf(0x5eed);
        BigInteger msg = EdDSAJubjub.hashToField("adr-0038 p4".getBytes());
        var keypair = EdDSAJubjub.keypairFromSecret(sk);

        @SuppressWarnings("deprecation")
        var viaDeprecated = EdDSAJubjub.sign(sk, msg);
        var viaKeypair = EdDSAJubjub.sign(keypair, msg);

        assertEquals(viaDeprecated.r(), viaKeypair.r(), "R must match across both entry points");
        assertEquals(viaDeprecated.s(), viaKeypair.s(), "S must match across both entry points");
        assertTrue(EdDSAJubjub.verify(keypair.pk(), msg, viaKeypair));
        assertTrue(EdDSAJubjub.verify(keypair.pk(), msg, viaDeprecated));
    }

    @Test
    void blindedPublicOutputsHaveDeterministicAffineRepresentations() {
        BigInteger sk = BigInteger.valueOf(0x5eed);
        BigInteger msg = EdDSAJubjub.hashToField("canonical output".getBytes());

        var keypair1 = EdDSAJubjub.keypairFromSecret(sk);
        var keypair2 = EdDSAJubjub.keypairFromSecret(sk);
        assertRawCoordinatesEqual(keypair1.pk(), keypair2.pk());
        assertEquals(BigInteger.ONE, keypair1.pk().z());

        var signature1 = EdDSAJubjub.sign(keypair1, msg);
        var signature2 = EdDSAJubjub.sign(keypair1, msg);
        assertRawCoordinatesEqual(signature1.r(), signature2.r());
        assertEquals(BigInteger.ONE, signature1.r().z());

        JubjubPoint commitment1 =
                PedersenCommitment.commit(BigInteger.valueOf(42), BigInteger.valueOf(12345));
        JubjubPoint commitment2 =
                PedersenCommitment.commit(BigInteger.valueOf(42), BigInteger.valueOf(12345));
        assertRawCoordinatesEqual(commitment1, commitment2);
        assertEquals(BigInteger.ONE, commitment1.z());

        JubjubPoint callerR = G.scalarMul(BigInteger.valueOf(42));
        var callerConstructed = new EdDSAJubjub.Signature(callerR, BigInteger.ZERO);
        assertSame(callerR, callerConstructed.r(),
                "an explicit caller-supplied representation must be preserved");
    }

    @Test
    void pedersenCommitmentIsUnchanged() {
        BigInteger v = BigInteger.valueOf(42), r = BigInteger.valueOf(12345);
        JubjubPoint c = PedersenCommitment.commit(v, r);

        // Recomputed the long way through the retained variable-time path.
        JubjubPoint expected = G.scalarMul(v).add(PedersenCommitment.H.scalarMul(r));
        assertEquals(expected, c);
        assertTrue(PedersenCommitment.verify(c, v, r));
    }

    @Test
    void pedersenHomomorphismStillHolds() {
        BigInteger v1 = BigInteger.valueOf(7), r1 = BigInteger.valueOf(11);
        BigInteger v2 = BigInteger.valueOf(9), r2 = BigInteger.valueOf(13);

        assertEquals(PedersenCommitment.commit(v1.add(v2), r1.add(r2)),
                PedersenCommitment.commit(v1, r1).add(PedersenCommitment.commit(v2, r2)));
    }

    /** Binding is to the residue mod l, as the Javadoc now states explicitly. */
    @Test
    void commitmentBindsTheResidueModL() {
        BigInteger v = BigInteger.valueOf(5), r = BigInteger.valueOf(9);
        assertEquals(PedersenCommitment.commit(v, r), PedersenCommitment.commit(v.add(L), r),
                "G has order l, so the commitment cannot distinguish v from v + l");
    }

    @Test
    void pedersenPublicVerificationPathMatchesSecretGenerationSemantics() {
        for (BigInteger[] opening : new BigInteger[][]{
                {BigInteger.ZERO, BigInteger.ZERO},
                {BigInteger.valueOf(-1), BigInteger.valueOf(-2)},
                {L.subtract(BigInteger.ONE), L.subtract(BigInteger.ONE)},
                {L, L},
                {L.add(BigInteger.valueOf(42)), L.multiply(BigInteger.TWO).add(BigInteger.valueOf(9))}
        }) {
            JubjubPoint commitment = PedersenCommitment.commit(opening[0], opening[1]);
            assertTrue(PedersenCommitment.verify(commitment, opening[0], opening[1]),
                    "public recomputation diverged at v=" + opening[0] + ", r=" + opening[1]);
            assertTrue(PedersenCommitment.verify(commitment,
                            opening[0].add(L), opening[1].subtract(L)),
                    "verification must preserve residue-mod-l semantics");
        }
    }

    @Test
    void commitmentOfZeroValueStillWorks() {
        BigInteger r = BigInteger.valueOf(999);
        assertEquals(PedersenCommitment.H.scalarMul(r), PedersenCommitment.commit(BigInteger.ZERO, r));
    }

    // ------------------------------------------------------------------
    //  Keypair is validated by construction
    // ------------------------------------------------------------------

    @Test
    void publicKeypairConstructorValidatesTheRelation() {
        BigInteger sk = BigInteger.valueOf(4242);
        JubjubPoint pk = G.scalarMul(sk);
        var keypair = new EdDSAJubjub.Keypair(sk, pk);
        assertEquals(sk, keypair.sk());
        assertEquals(pk, keypair.pk());
        assertSame(pk, keypair.pk(),
                "the compatibility constructor must preserve the caller's representation");

        assertThrows(IllegalArgumentException.class,
                () -> new EdDSAJubjub.Keypair(sk, G.scalarMul(sk.add(BigInteger.ONE))));
        assertThrows(IllegalArgumentException.class,
                () -> new EdDSAJubjub.Keypair(BigInteger.ZERO, JubjubPoint.IDENTITY));
    }

    @Test
    void keypairReplacementPreservesRecordLikeValueEquality() {
        BigInteger sk = BigInteger.valueOf(4242);
        JubjubPoint projectivePk = G.scalarMul(sk);
        record LegacyKeypair(BigInteger sk, JubjubPoint pk) {}

        var first = new EdDSAJubjub.Keypair(sk, projectivePk);
        var second = EdDSAJubjub.keypairFromSecret(sk);
        var different = EdDSAJubjub.keypairFromSecret(sk.add(BigInteger.ONE));

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertEquals(new LegacyKeypair(sk, projectivePk).hashCode(), first.hashCode(),
                "record-to-class migration must preserve the former two-component hash value");
        assertNotEquals(first, different);
        assertNotEquals(first, null);
    }

    @Test
    void keypairFactoriesEstablishTheRelation() {
        var fromSecret = EdDSAJubjub.keypairFromSecret(BigInteger.valueOf(4242));
        assertEquals(G.scalarMul(BigInteger.valueOf(4242)), fromSecret.pk());

        var generated = EdDSAJubjub.generateKeypair(new SecureRandom());
        assertEquals(G.scalarMul(generated.sk()), generated.pk());
        assertTrue(generated.sk().signum() > 0 && generated.sk().compareTo(L) < 0);
    }

    @Test
    void keypairToStringRedactsTheSecret() {
        var keypair = EdDSAJubjub.keypairFromSecret(BigInteger.valueOf(0xDEAD));
        String s = keypair.toString();
        assertTrue(s.contains("<redacted>"), s);
        assertFalse(s.contains(BigInteger.valueOf(0xDEAD).toString()), "sk leaked: " + s);
        assertFalse(s.contains(BigInteger.valueOf(0xDEAD).toString(16)), "sk leaked: " + s);
    }

    @Test
    void signRejectsOutOfRangeMessage() {
        var keypair = EdDSAJubjub.keypairFromSecret(BigInteger.valueOf(3));
        assertThrows(IllegalArgumentException.class,
                () -> EdDSAJubjub.sign(keypair, JubjubCurve.BASE_FIELD_PRIME));
    }

    @Test
    void verifyBeforeReleaseRejectsACorruptedCandidate() {
        BigInteger sk = BigInteger.valueOf(0x5eed);
        BigInteger msg = EdDSAJubjub.hashToField("fault check".getBytes());
        var keypair = EdDSAJubjub.keypairFromSecret(sk);
        var valid = EdDSAJubjub.sign(keypair, msg);
        var corrupted = new EdDSAJubjub.Signature(
                valid.r(), valid.s().add(BigInteger.ONE).mod(L));

        assertThrows(IllegalStateException.class,
                () -> EdDSAJubjub.verifyBeforeRelease(keypair.pk(), msg, corrupted));
        assertSame(valid,
                EdDSAJubjub.verifyBeforeRelease(keypair.pk(), msg, valid));
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static BigInteger[] interestingScalars() {
        return new BigInteger[]{
                BigInteger.ZERO,                       // was an early exit
                BigInteger.ONE,                        // 1 bit, weight 1
                BigInteger.valueOf(3),                 // 2 bits, weight 2
                BigInteger.ONE.shiftLeft(64),          // 65 bits, weight 1
                BigInteger.ONE.shiftLeft(200),         // 201 bits, weight 1
                BigInteger.ONE.shiftLeft(251),         // top bit only
                BigInteger.ONE.shiftLeft(200).subtract(BigInteger.ONE),  // 200 bits, full weight
                L.subtract(BigInteger.ONE),            // maximum in range
                L.shiftRight(1),                       // mid-range
        };
    }

    /** Counts group operations performed by the production fixed-schedule path. */
    private static Counter count(BigInteger k) {
        return observe(() -> G.scalarMulSecretRaw252UnsafeForTiming(k));
    }

    private static Counter countBlinded(BigInteger k, BigInteger m) {
        return observe(() -> G.scalarMulSecretBlindedBestEffort(k, m));
    }

    private static Counter observe(Supplier<?> operation) {
        Counter counter = new Counter();
        JubjubPoint.installSecretScheduleObserverForTesting(counter);
        try {
            assertNotNull(operation.get());
            return counter;
        } finally {
            JubjubPoint.clearSecretScheduleObserverForTesting();
        }
    }

    private static void assertSchedules(Counter counter, int expectedSchedules) {
        assertEquals(expectedSchedules, counter.schedules.size());
        assertTrue(counter.schedules.stream()
                        .allMatch(bits -> bits == JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS),
                "production call used an unblinded or variable-length schedule: "
                        + counter.schedules);
        assertEquals(expectedSchedules * JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS,
                counter.adds);
        assertEquals(expectedSchedules * JubjubPoint.SECRET_SCALAR_BLINDED_SCHEDULE_BITS,
                counter.doubles);
    }

    private static void assertRawCoordinatesEqual(JubjubPoint left, JubjubPoint right) {
        assertEquals(left.u(), right.u());
        assertEquals(left.v(), right.v());
        assertEquals(left.z(), right.z());
        assertEquals(left.t(), right.t());
    }

    private static final class Counter implements JubjubPoint.SecretScheduleObserver {
        int adds;
        int doubles;
        final List<Integer> schedules = new ArrayList<>();

        @Override
        public void scheduleStarted(int iterations) {
            schedules.add(iterations);
        }

        @Override
        public void addition() {
            adds++;
        }

        @Override
        public void doubling() {
            doubles++;
        }
    }
}
