package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0053 M2: {@link DkgParticipant} and {@link DkgTranscript} against honest runs, every
 * adversarial behaviour and omission in the ADR's M2 row, and the abort catalogue of spec §5.1.
 */
class DkgParticipantTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;

    private static DkgHarness.Delivery broadcastTo(DkgMessage m, int recipient, byte[] bytes) {
        return new DkgHarness.Delivery(m.sender(), recipient, bytes);
    }

    private static List<DkgHarness.Delivery> everyone(DkgHarness h, DkgMessage m, byte[] bytes) {
        List<DkgHarness.Delivery> out = new ArrayList<>();
        for (int j = 1; j <= h.config.n(); j++) out.add(broadcastTo(m, j, bytes));
        return out;
    }

    /** Asserts every non-aborted participant finished with the same context, and the shares match it. */
    private static ThresholdKeyContext agreed(DkgHarness h, Set<Integer> expectedAborted) {
        assertEquals(expectedAborted, h.aborted.keySet(), "aborted: " + h.aborted);
        ThresholdKeyContext context = null;
        for (DkgParticipant p : h.participants) {
            if (expectedAborted.contains(p.id())) continue;
            ThresholdKeyShare share = p.result();
            if (context == null) context = share.context();
            assertEquals(context, share.context(), "participant " + p.id());
            assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(share.secretScalar())
                    .projectiveEquals(context.verificationKey(p.id())), "share of " + p.id());
        }
        DkgTranscript.DkgPublicOutcome recomputed = DkgTranscript.of(h.config, h.transcriptMessages()).recompute();
        assertEquals(context.qual(), recomputed.qual());
        assertTrue(recomputed.jointKey().projectiveEquals(context.jointKey().point()));
        assertArrayEquals(DkgTranscript.of(h.config, h.transcriptMessages()).digest(), context.transcriptDigest());
        return context;
    }

    private static BigInteger combine(ThresholdKeyContext context, List<ThresholdKeyShare> shares, int[] subset) {
        BigInteger[] lambda = ThresholdMath.lagrangeAt(subset, 0);
        BigInteger x = BigInteger.ZERO;
        for (int i = 0; i < subset.length; i++) {
            x = x.add(lambda[i].multiply(shares.get(subset[i] - 1).secretScalar())).mod(L);
        }
        return x;
    }

    // ------------------------------------------------------------------ honest

    @Nested
    @DisplayName("Honest runs")
    class Honest {

        @Test
        @DisplayName("Every (t, n) up to (3, 7): all agree on QUAL, y and Y_j, and every (t + 1)-subset recombines the key")
        void honestRuns() {
            for (int[] tn : new int[][]{{1, 3}, {1, 4}, {2, 5}, {2, 6}, {3, 7}}) {
                DkgConfig config = DkgHarness.config(tn[0], tn[1], "honest", tn[0] * 100L + tn[1]);
                DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
                ThresholdKeyContext context = agreed(h, Set.of());
                assertEquals(tn[1], context.qual().size());
                List<ThresholdKeyShare> shares = new ArrayList<>();
                for (DkgParticipant p : h.participants) shares.add(p.result());
                BigInteger x = combine(context, shares, firstSubset(tn[0] + 1));
                assertTrue(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(x).projectiveEquals(context.jointKey().point()));
                int[] last = new int[tn[0] + 1];
                for (int i = 0; i <= tn[0]; i++) last[i] = tn[1] - tn[0] + i;
                assertEquals(x, combine(context, shares, last));
            }
        }

        @Test
        @DisplayName("The transcript digest does not depend on arrival order; secret shares are redacted")
        void shuffleAndRedaction() {
            DkgConfig config = DkgHarness.config(1, 3, "shuffle", 1);
            DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
            List<byte[]> messages = new ArrayList<>(h.transcriptMessages());
            byte[] digest = DkgTranscript.of(config, messages).digest();
            for (int i = 0; i < 5; i++) {
                Collections.shuffle(messages, new Random(i));
                assertArrayEquals(digest, DkgTranscript.of(config, messages).digest());
            }
            messages.add(messages.get(0)); // a byte-identical duplicate counts once
            assertArrayEquals(digest, DkgTranscript.of(config, messages).digest());
            ThresholdKeyShare share = h.participant(1).result();
            assertFalse(share.toString().contains(share.secretScalar().toString()));
        }
    }

    private static int[] firstSubset(int size) {
        int[] s = new int[size];
        for (int i = 0; i < size; i++) s[i] = i + 1;
        return s;
    }

    // ------------------------------------------------------------------ adversarial

    @Nested
    @DisplayName("Adversarial simulations")
    class Adversarial {

        @Test
        @DisplayName("A bad share is complained about and answered; the dealer stays qualified")
        void badShareAnswered() {
            DkgConfig config = DkgHarness.config(1, 3, "bad-share", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 1);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2) {
                    return List.of(new DkgHarness.Delivery(1, 2, DkgMessage.pair(config, DkgMessage.Kind.SHARE, 1, 2,
                            m.s().add(BigInteger.ONE).mod(L), m.sPrime()).encode()));
                }
                return honest;
            }).run();
            ThresholdKeyContext c = agreed(h, Set.of());
            assertEquals(Set.of(1, 2, 3), c.qual());
            assertTrue(c.jointKey().point().projectiveEquals(DkgHarness.trueKey(d, List.of(1, 2, 3))));
        }

        @Test
        @DisplayName("A false complaint against an honest dealer is answered; nothing changes")
        void falseComplaint() {
            DkgConfig config = DkgHarness.config(1, 3, "false-complaint", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 2);
            DkgHarness h = DkgHarness.fixed(config, d, DkgHarness.HONEST)
                    .inject(DkgMessage.complaint(config, 3, 1)) // participant 3 complains without cause
                    .run();
            ThresholdKeyContext c = agreed(h, Set.of());
            assertEquals(Set.of(1, 2, 3), c.qual());
            assertTrue(c.jointKey().point().projectiveEquals(DkgHarness.trueKey(d, List.of(1, 2, 3))));
            assertEquals(1, DkgTranscript.of(config, h.transcriptMessages()).roundMessages(3).size(), "dealer 1 answered");
        }

        @Test
        @DisplayName("More than t complaints disqualify the dealer")
        void tooManyComplaints() {
            DkgConfig config = DkgHarness.config(2, 5, "many-complaints", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(2, 5, 3);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() >= 3) {
                    return List.of(new DkgHarness.Delivery(1, m.subject(), DkgMessage.pair(config, DkgMessage.Kind.SHARE, 1,
                            m.subject(), m.s().add(BigInteger.ONE).mod(L), m.sPrime()).encode()));
                }
                if (m.kind() == DkgMessage.Kind.ANSWER && m.sender() == 1) {
                    return honest; // even correct answers cannot save a dealer with > t complaints
                }
                return honest;
            }).run();
            ThresholdKeyContext c = agreed(h, Set.of(1));
            assertEquals(Set.of(2, 3, 4, 5), c.qual());
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED, h.aborted.get(1).reason());
        }

        @Test
        @DisplayName("A complaint answered with a pair that fails (4) disqualifies the dealer")
        void badAnswer() {
            DkgConfig config = DkgHarness.config(1, 3, "bad-answer", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 4);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2) {
                    return List.of(new DkgHarness.Delivery(1, 2, DkgMessage.pair(config, DkgMessage.Kind.SHARE, 1, 2,
                            m.s().add(BigInteger.ONE).mod(L), m.sPrime()).encode()));
                }
                if (m.kind() == DkgMessage.Kind.ANSWER && m.sender() == 1) {
                    byte[] bad = DkgMessage.pair(config, DkgMessage.Kind.ANSWER, 1, m.subject(),
                            m.s().add(BigInteger.ONE).mod(L), m.sPrime()).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(1, x.recipient(), bad));
                    return out;
                }
                return honest;
            }).run();
            ThresholdKeyContext c = agreed(h, Set.of(1));
            assertEquals(Set.of(2, 3), c.qual());
        }

        @Test
        @DisplayName("Phase-2 Feldman cheat: a false A_i is complained about and reconstructed; the key is unchanged")
        void feldmanCheat() {
            DkgConfig config = DkgHarness.config(1, 3, "feldman-cheat", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 5);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 3) {
                    List<JubjubPoint> forged = new ArrayList<>(m.points());
                    forged.set(1, forged.get(1).add(JubjubPoint.SUBGROUP_GENERATOR).normalized());
                    byte[] bytes = DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, 3, forged).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(3, x.recipient(), bytes));
                    return out;
                }
                return honest;
            }).run();
            // The others' valid complaints mark dealer 3, which then aborts (A8).
            ThresholdKeyContext c = agreed(h, Set.of(3));
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED, h.aborted.get(3).reason());
            assertEquals(Set.of(1, 2, 3), c.qual());
            assertTrue(c.jointKey().point().projectiveEquals(DkgHarness.trueKey(d, List.of(1, 2, 3))));
            assertEquals(Set.of(3), DkgTranscript.of(config, h.transcriptMessages()).recompute().marked());
        }

        @Test
        @DisplayName("Rushing order: a dealer choosing A_i0 after seeing the honest values cannot bias y")
        void rushing() {
            DkgConfig config = DkgHarness.config(1, 3, "rushing", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 6);
            JubjubPoint target = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(424242));
            JubjubPoint honestSum = d.get(0).extraction().get(0).add(d.get(1).extraction().get(0));
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 3) {
                    List<JubjubPoint> biased = new ArrayList<>(m.points());
                    biased.set(0, target.add(honestSum.negate()).normalized()); // makes Σ A_i0 = target
                    byte[] bytes = DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, 3, biased).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(3, x.recipient(), bytes));
                    return out;
                }
                return honest;
            }).run();
            ThresholdKeyContext c = agreed(h, Set.of(3));
            assertFalse(c.jointKey().point().projectiveEquals(target), "the bias attempt failed");
            assertTrue(c.jointKey().point().projectiveEquals(DkgHarness.trueKey(d, List.of(1, 2, 3))));
        }

        @Test
        @DisplayName("Replays from another session, round or target, and mismatched senders, are refused")
        void replays() {
            DkgConfig config = DkgHarness.config(1, 3, "replay", 1);
            DkgConfig other = DkgHarness.config(1, 3, "replay", 2);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 7);
            DkgParticipant p = DkgParticipant.withDealing(config, 1, d.get(0));
            DkgParticipant q = DkgParticipant.withDealing(other, 2, d.get(1));
            p.start();
            List<DkgMessage> foreign = q.start();
            assertThrows(IllegalArgumentException.class, () -> p.receiveBroadcast(2, foreign.get(0).encode()), "another attempt");
            DkgParticipant sender = DkgParticipant.withDealing(config, 2, d.get(1));
            List<DkgMessage> out = sender.start();
            byte[] commitments = out.get(0).encode();
            assertThrows(IllegalArgumentException.class, () -> p.receiveBroadcast(3, commitments), "sender mismatch");
            assertThrows(IllegalArgumentException.class, () -> p.receivePrivate(2, commitments), "a broadcast kind on the private channel");
            byte[] shareForThree = out.stream().filter(m -> m.kind() == DkgMessage.Kind.SHARE && m.subject() == 3)
                    .findFirst().orElseThrow().encode();
            assertThrows(IllegalArgumentException.class, () -> p.receivePrivate(2, shareForThree), "another target");
            byte[] shareForOne = out.stream().filter(m -> m.kind() == DkgMessage.Kind.SHARE && m.subject() == 1)
                    .findFirst().orElseThrow().encode();
            assertThrows(IllegalArgumentException.class, () -> p.receiveBroadcast(2, shareForOne), "a SHARE on the broadcast channel");
            byte[] complaint = DkgMessage.complaint(config, 2, 1).encode();
            assertThrows(IllegalArgumentException.class, () -> p.receiveBroadcast(2, complaint), "a round-2 message in round 1");
        }

        @Test
        @DisplayName("Non-canonical scalars and non-subgroup points do not decode")
        void malformed() {
            DkgConfig config = DkgHarness.config(1, 3, "malformed", 1);
            ThresholdVss.Dealing d = DkgHarness.dealings(1, 3, 8).get(0);
            byte[] good = DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, 1, d.commitments()).encode();
            byte[] torsion = good.clone();
            JubjubPoint t8 = JubjubPoint.FULL_GENERATOR.scalarMul(L);
            System.arraycopy(d.commitments().get(0).add(t8).toBytes(), 0, torsion, DkgMessage.HEADER_BYTES, 32);
            assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, torsion));
            byte[] share = DkgMessage.pair(config, DkgMessage.Kind.SHARE, 1, 2, BigInteger.ONE, BigInteger.TWO).encode();
            System.arraycopy(DkgMessage.i2osp32(L), 0, share, DkgMessage.HEADER_BYTES, 32);
            assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, share));
            assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, Arrays.copyOf(good, good.length - 1)));
        }
    }

    // ------------------------------------------------------------------ omissions

    @Nested
    @DisplayName("Omissions and conflicts")
    class Omissions {

        @Test
        @DisplayName("A missing commitment vector disqualifies the dealer")
        void missingCommitments() {
            DkgConfig config = DkgHarness.config(1, 3, "missing-c", 1);
            DkgHarness h = DkgHarness.random(config, (m, honest) ->
                    m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() == 3 ? List.of() : honest).run();
            ThresholdKeyContext c = agreed(h, Set.of(3));
            assertEquals(Set.of(1, 2), c.qual());
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED, h.aborted.get(3).reason());
        }

        @Test
        @DisplayName("A single unanswered complaint (n = 3, t = 1) disqualifies the dealer")
        void unansweredComplaint() {
            DkgConfig config = DkgHarness.config(1, 3, "unanswered", 1);
            DkgHarness h = DkgHarness.random(config, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2) return List.of();
                if (m.kind() == DkgMessage.Kind.ANSWER && m.sender() == 1) return List.of();
                return honest;
            }).run();
            ThresholdKeyContext c = agreed(h, Set.of(1));
            assertEquals(Set.of(2, 3), c.qual());
        }

        @Test
        @DisplayName("Conflicting commitment vectors disqualify; conflicting extraction vectors are reconstructed")
        void conflicts() {
            DkgConfig config = DkgHarness.config(1, 3, "conflicts", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 9);
            List<ThresholdVss.Dealing> alt = DkgHarness.dealings(1, 3, 10);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() == 3) {
                    byte[] second = DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, 3, alt.get(2).commitments()).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>(honest);
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(3, x.recipient(), second));
                    return out;
                }
                return honest;
            }).run();
            assertEquals(Set.of(1, 2), agreed(h, Set.of(3)).qual());

            DkgHarness h2 = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 2) {
                    byte[] second = DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, 2, alt.get(1).extraction()).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>(honest);
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(2, x.recipient(), second));
                    return out;
                }
                return honest;
            }).run();
            ThresholdKeyContext c = agreed(h2, Set.of(2));
            assertTrue(c.jointKey().point().projectiveEquals(DkgHarness.trueKey(d, List.of(1, 2, 3))));
        }

        @Test
        @DisplayName("A withheld extraction vector is reconstructed: the key equals the run without withholding")
        void withheldExtraction() {
            DkgConfig config = DkgHarness.config(2, 5, "withheld", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(2, 5, 11);
            ThresholdKeyContext honest = agreed(DkgHarness.fixed(config, d, DkgHarness.HONEST).run(), Set.of());
            DkgHarness h = DkgHarness.fixed(config, d, (m, h0) ->
                    m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 4 ? List.of() : h0).run();
            ThresholdKeyContext c = agreed(h, Set.of(4));
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED, h.aborted.get(4).reason());
            assertTrue(c.jointKey().point().projectiveEquals(honest.jointKey().point()));
            for (int j = 1; j <= 5; j++) {
                assertTrue(c.verificationKey(j).projectiveEquals(honest.verificationKey(j)));
            }
            assertEquals(honest, c, "same session, QUAL and keys: the same context (spec §9)");
            assertFalse(Arrays.equals(honest.transcriptDigest(), c.transcriptDigest()), "but a different record");
        }

        @Test
        @DisplayName("Too few reconstruction pairs abort with 'fault assumption violated'")
        void tooFewPairs() {
            DkgConfig config = DkgHarness.config(1, 3, "few-pairs", 1);
            DkgHarness h = DkgHarness.random(config, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 3) return List.of();
                if (m.kind() == DkgMessage.Kind.RECONSTRUCTION && m.sender() == 2) return List.of();
                return honest;
            }).run();
            for (int id : List.of(1, 2)) {
                assertEquals(FaultAssumptionViolatedException.Reason.TOO_FEW_RECONSTRUCTION_PAIRS, h.aborted.get(id).reason());
            }
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED, h.aborted.get(3).reason());
        }
    }

    // ------------------------------------------------------------------ aborts

    @Nested
    @DisplayName("Abort catalogue (spec §5.1)")
    class Aborts {

        @Test
        @DisplayName("A1: fewer than n − t qualified dealers")
        void tooFewQualified() {
            DkgConfig config = DkgHarness.config(1, 3, "a1", 1);
            DkgHarness h = DkgHarness.random(config, (m, honest) ->
                    m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() >= 2 ? List.of() : honest).run();
            assertEquals(FaultAssumptionViolatedException.Reason.TOO_FEW_QUALIFIED, h.aborted.get(1).reason());
        }

        @Test
        @DisplayName("A5: polynomials whose constant terms sum to 0 give y = O and abort")
        void identityKey() {
            DkgConfig config = DkgHarness.config(1, 3, "a5", 1);
            List<ThresholdVss.Dealing> d = List.of(
                    ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.ONE, BigInteger.TWO}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}),
                    ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.TWO, BigInteger.ONE}, new BigInteger[]{BigInteger.TWO, BigInteger.ONE}),
                    ThresholdVss.dealWithCoefficients(new BigInteger[]{L.subtract(BigInteger.valueOf(3)), BigInteger.TEN}, new BigInteger[]{BigInteger.TEN, BigInteger.ONE}));
            DkgHarness h = DkgHarness.fixed(config, d, DkgHarness.HONEST).run();
            for (int id : List.of(1, 2, 3)) {
                assertEquals(FaultAssumptionViolatedException.Reason.IDENTITY_JOINT_KEY, h.aborted.get(id).reason());
            }
        }

        @Test
        @DisplayName("A6: a participant whose own extraction complaint was dropped from its view sees a share mismatch")
        void shareMismatch() {
            DkgConfig config = DkgHarness.config(1, 3, "a6", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 12);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 3) {
                    List<JubjubPoint> forged = new ArrayList<>(m.points());
                    forged.set(1, forged.get(1).add(JubjubPoint.SUBGROUP_GENERATOR).normalized());
                    byte[] bytes = DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, 3, forged).encode();
                    List<DkgHarness.Delivery> out = new ArrayList<>();
                    for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(3, x.recipient(), bytes));
                    return out;
                }
                if (m.kind() == DkgMessage.Kind.EXTRACTION_COMPLAINT) {
                    // broadcast without agreement: participant 1 never sees any complaint
                    return honest.stream().filter(x -> x.recipient() != 1).toList();
                }
                return honest;
            }).run();
            assertEquals(FaultAssumptionViolatedException.Reason.SHARE_MISMATCH, h.aborted.get(1).reason());
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED, h.aborted.get(3).reason());
        }

        @Test
        @DisplayName("A8: if every dealer's EXTRACTION is late, every participant aborts; nobody confirms, so the run cannot be admitted")
        void allExtractionsLate() {
            DkgConfig config = DkgHarness.config(1, 3, "a8", 1);
            DkgHarness h = DkgHarness.random(config, (m, honest) ->
                    m.kind() == DkgMessage.Kind.EXTRACTION ? List.of() : honest).run();
            for (int id : List.of(1, 2, 3)) {
                assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED, h.aborted.get(id).reason());
            }
            assertTrue(h.confirmations().isEmpty(), "no confirmations: admission needs t + 1");
        }

        @Test
        @DisplayName("A7: up to t lying confirmations are ignored; t + 1 differing confirmations abort the rest")
        void conflictingConfirmations() {
            DkgConfig config = DkgHarness.config(1, 3, "a7", 1);
            DkgHarness oneLie = DkgHarness.random(config, (m, honest) -> lie(config, m, honest, Set.of(2))).run();
            agreed(oneLie, Set.of());
            DkgHarness twoLies = DkgHarness.random(config, (m, honest) -> lie(config, m, honest, Set.of(2, 3))).run();
            assertEquals(FaultAssumptionViolatedException.Reason.CONFLICTING_CONFIRMATION, twoLies.aborted.get(1).reason());
        }

        private List<DkgHarness.Delivery> lie(DkgConfig config, DkgMessage m, List<DkgHarness.Delivery> honest, Set<Integer> liars) {
            if (m.kind() == DkgMessage.Kind.CONFIRMATION && liars.contains(m.sender())) {
                byte[] lie = DkgMessage.confirmation(config, m.sender(), new byte[32], m.confirmedKey()).encode();
                List<DkgHarness.Delivery> out = new ArrayList<>();
                for (DkgHarness.Delivery x : honest) out.add(new DkgHarness.Delivery(m.sender(), x.recipient(), lie));
                return out;
            }
            return honest;
        }

        @Test
        @DisplayName("I1: parameters outside t >= 1, 2t + 1 <= n <= 64 are refused")
        void parameters() {
            assertThrows(IllegalArgumentException.class, () -> DkgHarness.config(0, 3, "x", 1));
            assertThrows(IllegalArgumentException.class, () -> DkgHarness.config(2, 4, "x", 1));
            assertThrows(IllegalArgumentException.class, () -> DkgHarness.config(1, 65, "x", 1));
            assertThrows(IllegalArgumentException.class,
                    () -> DkgConfig.create(1, 3, List.of(new byte[1], new byte[1]), new byte[0], 1));
            assertThrows(IllegalArgumentException.class,
                    () -> DkgConfig.create(1, 3, List.of(new byte[1], new byte[0], new byte[1]), new byte[0], 1));
        }

        @Test
        @DisplayName("I16: contexts and sessions from different attempts are never equal")
        void attempts() {
            DkgConfig a = DkgHarness.config(1, 3, "attempts", 1);
            DkgConfig b = DkgHarness.config(1, 3, "attempts", 2);
            assertNotEquals(a, b);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 13);
            ThresholdKeyContext ca = agreed(DkgHarness.fixed(a, d, DkgHarness.HONEST).run(), Set.of());
            ThresholdKeyContext cb = agreed(DkgHarness.fixed(b, d, DkgHarness.HONEST).run(), Set.of());
            assertTrue(ca.jointKey().point().projectiveEquals(cb.jointKey().point()), "same polynomials, same key");
            assertNotEquals(ca, cb, "but different attempts");
        }
    }

    // ------------------------------------------------------------------ review round 1 (ADR-0053)

    @Nested
    @DisplayName("Review round 1: sticky aborts, A9, the A7 matching rule, restore, roster")
    class ReviewRound1 {

        @Test
        @DisplayName("An abort is final: late messages and further closeRound/result calls are refused")
        void abortsAreSticky() {
            DkgConfig config = DkgHarness.config(1, 3, "sticky", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 31);
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) ->
                    m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() == 3 ? List.of() : honest).run();
            DkgParticipant p3 = h.participant(3);
            FaultAssumptionViolatedException first = h.aborted.get(3);
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED, first.reason());
            byte[] late = DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, 3, d.get(2).commitments()).encode();
            assertThrows(FaultAssumptionViolatedException.class, () -> p3.receiveBroadcast(3, late));
            assertThrows(FaultAssumptionViolatedException.class, p3::closeRound);
            assertThrows(FaultAssumptionViolatedException.class, p3::result);
        }

        @Test
        @DisplayName("A9: a participant whose own complaint is missing from its view aborts (no NPE, no unchecked adoption)")
        void ownComplaintMissing() {
            DkgConfig config = DkgHarness.config(1, 3, "a9", 1);
            DkgHarness h = DkgHarness.random(config, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2) return List.of();
                if (m.kind() == DkgMessage.Kind.COMPLAINT && m.sender() == 2) {
                    return honest.stream().filter(x -> x.recipient() != 2).toList(); // not delivered back to 2
                }
                return honest;
            }).run();
            assertEquals(FaultAssumptionViolatedException.Reason.OWN_COMPLAINT_MISSING, h.aborted.get(2).reason());
        }

        @Test
        @DisplayName("A7: a participant on a minority view (fewer than t + 1 matching confirmations) aborts instead of finishing")
        void minorityViewAborts() {
            DkgConfig config = DkgHarness.config(1, 3, "minority", 1);
            List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 32);
            List<ThresholdVss.Dealing> alt = DkgHarness.dealings(1, 3, 33);
            // Dealer 3 equivocates privately: participant 2 also receives (as if broadcast) a
            // second, conflicting COMMITMENTS, so 2 alone disqualifies dealer 3.
            DkgHarness h = DkgHarness.fixed(config, d, (m, honest) -> {
                if (m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() == 3) {
                    List<DkgHarness.Delivery> out = new ArrayList<>(honest);
                    out.add(new DkgHarness.Delivery(3, 2, DkgMessage.points(config, DkgMessage.Kind.COMMITMENTS, 3,
                            alt.get(2).commitments()).encode()));
                    return out;
                }
                return honest;
            }).run();
            assertEquals(FaultAssumptionViolatedException.Reason.CONFLICTING_CONFIRMATION, h.aborted.get(2).reason(),
                    "participant 2's own view has only its own matching confirmation");
            assertFalse(h.aborted.containsKey(1));
        }

        @Test
        @DisplayName("ThresholdKeyShare.restore checks QUAL membership and [x]G = Y_j")
        void restore() {
            DkgConfig config = DkgHarness.config(1, 3, "restore", 1);
            DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
            ThresholdKeyShare s1 = h.participant(1).result();
            ThresholdKeyContext ctx = s1.context();
            ThresholdKeyShare again = ThresholdKeyShare.restore(ctx, 1, s1.secretScalar());
            assertEquals(s1.secretScalar(), again.secretScalar());
            assertThrows(IllegalArgumentException.class, () -> ThresholdKeyShare.restore(ctx, 2, s1.secretScalar()));
            assertThrows(IllegalArgumentException.class, () -> ThresholdKeyShare.restore(ctx, 4, s1.secretScalar()));
            assertThrows(IllegalArgumentException.class, () -> ThresholdKeyShare.restore(ctx, 1, L));
        }

        @Test
        @DisplayName("Duplicate roster keys are refused")
        void duplicateRoster() {
            byte[] key = new byte[32];
            assertThrows(IllegalArgumentException.class,
                    () -> DkgConfig.create(1, 3, List.of(key, key.clone(), new byte[]{1}), new byte[0], 1));
        }
    }
}
