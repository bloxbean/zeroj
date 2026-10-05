package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0053 M2, admission (D4a; spec §8). The test authenticator is a keyed hash under each
 * roster key, standing in for a signature. Round closure is checked against the board's real
 * delivered sets. Each rejection in the ADR's M2 row has a test: a fabricated record, an
 * omitted complaint or answer, a truncated round, a conflicting configuration, a replay from
 * another attempt, and too few confirmations.
 */
class DkgAdmissionTest {

    private static byte[] tag(byte[] key, byte[] message) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(key);
            sha.update(message);
            return sha.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Signs with the sender's roster key, as the sender's own transport would. */
    private static List<AuthenticatedDkgMessage> signed(DkgConfig config, List<byte[]> messages) {
        List<AuthenticatedDkgMessage> out = new ArrayList<>();
        for (byte[] m : messages) {
            int sender = m[34] & 0xFF;
            out.add(new AuthenticatedDkgMessage(m, tag(config.rosterKey(sender), m)));
        }
        return out;
    }

    /** Like {@link #signed}, tolerating bytes too short to carry a sender (signed as participant 1). */
    private static List<AuthenticatedDkgMessage> signedLenient(DkgConfig config, List<byte[]> messages) {
        List<AuthenticatedDkgMessage> out = new ArrayList<>();
        for (byte[] m : messages) {
            int sender = m.length > 34 ? m[34] & 0xFF : 1;
            sender = sender >= 1 && sender <= config.n() ? sender : 1;
            out.add(new AuthenticatedDkgMessage(m, tag(config.rosterKey(sender), m)));
        }
        return out;
    }

    /** Authenticity by keyed hash; closure by comparison with the board's actual round sets (1–6). */
    private static DkgAdmissionVerifier verifier(DkgConfig boardConfig, List<byte[]> boardMessages) {
        return verifier(boardConfig, boardMessages, null);
    }

    /**
     * As above, and round 7 compared with the board's actual confirmations. A {@code null}
     * round-7 board models "the board's round 7 is exactly what was submitted".
     */
    private static DkgAdmissionVerifier verifier(DkgConfig boardConfig, List<byte[]> boardMessages, List<byte[]> boardConfirmations) {
        DkgTranscript board = DkgTranscript.of(boardConfig, boardMessages);
        DkgRound round7 = new DkgRound(7);
        if (boardConfirmations != null) {
            for (byte[] c : boardConfirmations) round7.add(DkgMessage.decode(boardConfig, c));
        }
        return new DkgAdmissionVerifier() {
            @Override
            public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
                return Arrays.equals(tag(rosterKey, message), authenticator);
            }

            @Override
            public boolean roundClosed(DkgConfig config, int round, List<byte[]> canonicalMessages, byte[] evidence) {
                if (round == 7) {
                    if (boardConfirmations == null) return true;
                    List<byte[]> actual7 = new ArrayList<>();
                    for (DkgMessage m : round7.canonical()) actual7.add(m.encode());
                    return sameList(actual7, canonicalMessages);
                }
                List<byte[]> actual = board.roundMessages(round);
                if (actual.size() != canonicalMessages.size()) return false;
                for (int i = 0; i < actual.size(); i++) {
                    if (!Arrays.equals(actual.get(i), canonicalMessages.get(i))) return false;
                }
                return true;
            }
        };
    }

    private static boolean sameList(List<byte[]> a, List<byte[]> b) {
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) {
            if (!Arrays.equals(a.get(i), b.get(i))) return false;
        }
        return true;
    }

    private static final DkgAdmissionVerifier LENIENT_CLOSURE = new DkgAdmissionVerifier() {
        @Override
        public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
            return Arrays.equals(tag(rosterKey, message), authenticator);
        }

        @Override
        public boolean roundClosed(DkgConfig config, int round, List<byte[]> canonicalMessages, byte[] evidence) {
            return true;
        }
    };

    /** A run with a complaint and an answer in it, so omissions are testable. */
    private static DkgHarness runWithComplaint(DkgConfig config) {
        List<ThresholdVss.Dealing> d = DkgHarness.dealings(1, 3, 21);
        return DkgHarness.fixed(config, d, (m, honest) -> {
            if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2) {
                return List.of(new DkgHarness.Delivery(1, 2, DkgMessage.pair(config, DkgMessage.Kind.SHARE, 1, 2,
                        m.s().add(BigInteger.ONE).mod(JubjubCurve.SUBGROUP_ORDER), m.sPrime()).encode()));
            }
            return honest;
        }).run();
    }

    private static final Map<Integer, byte[]> NO_EVIDENCE = new HashMap<>();

    @Test
    @DisplayName("A complete, authenticated, closed and confirmed run is admitted, equal to the participants' own context")
    void admitted() {
        DkgConfig config = DkgHarness.config(1, 3, "admission", 1);
        DkgHarness h = runWithComplaint(config);
        ThresholdKeyContext admitted = ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signed(config, h.confirmations()), verifier(config, h.transcriptMessages(), h.confirmations()));
        assertEquals(h.participant(1).result().context(), admitted);
        assertEquals(Set.of(1, 2, 3), admitted.qual());
    }

    @Test
    @DisplayName("A fabricated record whose key its author knows (y = 9G) is refused without the others' authentication")
    void fabricated() {
        DkgConfig config = DkgHarness.config(1, 3, "admission", 1);
        // One party simulates all three dealers with polynomials it chose, so it knows x = 9.
        List<ThresholdVss.Dealing> forged = List.of(
                ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.TWO, BigInteger.ONE}, new BigInteger[]{BigInteger.ONE, BigInteger.ONE}),
                ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.valueOf(3), BigInteger.ONE}, new BigInteger[]{BigInteger.ONE, BigInteger.TWO}),
                ThresholdVss.dealWithCoefficients(new BigInteger[]{BigInteger.valueOf(4), BigInteger.ONE}, new BigInteger[]{BigInteger.TWO, BigInteger.ONE}));
        DkgHarness fake = DkgHarness.fixed(config, forged, DkgHarness.HONEST).run();
        assertTrue(fake.participant(1).result().context().jointKey().point()
                .projectiveEquals(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(9))));
        // The forger can authenticate only as itself (participant 1).
        List<AuthenticatedDkgMessage> asOne = new ArrayList<>();
        for (byte[] m : fake.transcriptMessages()) asOne.add(new AuthenticatedDkgMessage(m, tag(config.rosterKey(1), m)));
        List<AuthenticatedDkgMessage> confirmationsAsOne = new ArrayList<>();
        for (byte[] m : fake.confirmations()) confirmationsAsOne.add(new AuthenticatedDkgMessage(m, tag(config.rosterKey(1), m)));
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, asOne, NO_EVIDENCE,
                confirmationsAsOne, LENIENT_CLOSURE));
    }

    @Test
    @DisplayName("An omitted complaint or answer is refused by closure evidence, and by the confirmations")
    void omitted() {
        DkgConfig config = DkgHarness.config(1, 3, "admission", 1);
        DkgHarness h = runWithComplaint(config);
        for (int round : List.of(2, 3)) {
            List<byte[]> partial = new ArrayList<>();
            for (byte[] m : h.transcriptMessages()) if ((m[32] & 0xFF) != round) partial.add(m);
            assertTrue(partial.size() < h.transcriptMessages().size(), "round " + round + " had a message");
            assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, signed(config, partial),
                    NO_EVIDENCE, signed(config, h.confirmations()), verifier(config, h.transcriptMessages())),
                    "closure, round " + round);
            // Even a verifier that skips closure is stopped: honest confirmations commit to the full digest.
            Exception e = assertThrows(RuntimeException.class, () -> ThresholdKeyContext.admit(config, signed(config, partial),
                    NO_EVIDENCE, signed(config, h.confirmations()), LENIENT_CLOSURE));
            assertTrue(e instanceof IllegalArgumentException || e instanceof FaultAssumptionViolatedException, e.toString());
        }
    }

    @Test
    @DisplayName("A truncated round is refused")
    void truncated() {
        DkgConfig config = DkgHarness.config(2, 5, "admission", 1);
        DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
        List<byte[]> truncated = new ArrayList<>();
        int dropped = 0;
        for (byte[] m : h.transcriptMessages()) {
            if ((m[32] & 0xFF) == 4 && dropped == 0) { dropped++; continue; }
            truncated.add(m);
        }
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, signed(config, truncated),
                NO_EVIDENCE, signed(config, h.confirmations()), verifier(config, h.transcriptMessages())));
    }

    @Test
    @DisplayName("A conflicting roster or configuration, or a replay from another attempt, is refused")
    void otherConfiguration() {
        DkgConfig config = DkgHarness.config(1, 3, "admission", 1);
        DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
        DkgConfig nextAttempt = DkgHarness.config(1, 3, "admission", 2);
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= 3; j++) roster.add(config.rosterKey(j));
        roster.set(2, new byte[]{9, 9, 9});
        DkgConfig otherRoster = DkgConfig.create(1, 3, roster, config.applicationContext(), config.attempt());
        for (DkgConfig wrong : List.of(nextAttempt, otherRoster)) {
            assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(wrong, signed(config, h.transcriptMessages()),
                    NO_EVIDENCE, signed(config, h.confirmations()), LENIENT_CLOSURE));
        }
    }

    @Test
    @DisplayName("Fewer than t + 1 confirmations are refused; a confirmation of another record is refused outright")
    void confirmations() {
        DkgConfig config = DkgHarness.config(2, 5, "admission", 1);
        DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
        DkgAdmissionVerifier v = verifier(config, h.transcriptMessages());
        List<byte[]> two = h.confirmations().subList(0, 2);
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signed(config, two), v), "t = 2 confirmations");
        List<byte[]> duplicated = new ArrayList<>(two);
        duplicated.addAll(two);
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signed(config, duplicated), v), "repeats count once");
        ThresholdKeyContext ok = ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signed(config, h.confirmations().subList(0, 3)), v);
        assertEquals(h.participant(1).result().context(), ok);
        // Up to t lies from qualified participants do not veto; t + 1 differing confirmations refuse.
        List<byte[]> withLies = new ArrayList<>(h.confirmations().subList(0, 3));
        withLies.add(DkgMessage.confirmation(config, 4, new byte[32], ok.jointKey().point()).encode());
        withLies.add(DkgMessage.confirmation(config, 5, new byte[32], ok.jointKey().point()).encode());
        assertEquals(ok, ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signed(config, withLies), v), "t = 2 lies are ignored");
        List<byte[]> disagreement = new ArrayList<>(h.confirmations().subList(0, 3));
        for (int j = 3; j <= 5; j++) {
            disagreement.add(DkgMessage.confirmation(config, j, new byte[32], ok.jointKey().point()).encode());
        }
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signed(config, disagreement), v), "t + 1 = 3 differing confirmations");
        // A malformed or stale confirmation is ignored, never a veto.
        DkgConfig stale = DkgHarness.config(2, 5, "admission", 99);
        List<byte[]> withStale = new ArrayList<>(h.confirmations().subList(0, 3));
        withStale.add(DkgMessage.confirmation(stale, 4, new byte[32], ok.jointKey().point()).encode());
        withStale.add(new byte[7]);
        assertEquals(ok, ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, signedLenient(config, withStale), v));
        List<AuthenticatedDkgMessage> unauthenticated = new ArrayList<>(signed(config, h.confirmations().subList(0, 2)));
        byte[] third = h.confirmations().get(2);
        unauthenticated.add(new AuthenticatedDkgMessage(third, new byte[32]));
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, signed(config, h.transcriptMessages()),
                NO_EVIDENCE, unauthenticated, v), "an unauthenticated confirmation does not count");
    }

    @Test
    @DisplayName("n = 2t + 2: t + 1 differing confirmations refuse; omitting them fails round-7 closure; an equivocator counts as differing")
    void differingRuleObservable() {
        DkgConfig config = DkgHarness.config(1, 4, "admission-2of4", 1);
        DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
        ThresholdKeyContext context = h.participant(1).result().context();
        JubjubPoint y = context.jointKey().point();
        byte[] other = new byte[32];
        other[0] = 1;
        List<byte[]> board = new ArrayList<>();
        board.add(h.confirmations().stream().filter(c -> (c[34] & 0xFF) == 1).findFirst().orElseThrow());
        board.add(h.confirmations().stream().filter(c -> (c[34] & 0xFF) == 2).findFirst().orElseThrow());
        board.add(DkgMessage.confirmation(config, 3, other, y).encode());
        board.add(DkgMessage.confirmation(config, 4, other, y).encode());
        var transcript = signed(config, h.transcriptMessages());
        // Two matching, two differing (t + 1 = 2): an honest participant saw another board.
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE,
                signed(config, board), verifier(config, h.transcriptMessages(), board)));
        // Leaving out the differing ones is caught by round-7 closure (N6).
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE,
                signed(config, board.subList(0, 2)), verifier(config, h.transcriptMessages(), board)));
        // Equivocation: participant 2 sends a matching and a differing confirmation and counts as
        // differing only. Matching {1, 3}, differing {2}: one differing is at most t, so admitted.
        List<byte[]> equivocation = new ArrayList<>();
        equivocation.add(board.get(0));
        equivocation.add(board.get(1));
        equivocation.add(DkgMessage.confirmation(config, 2, other, y).encode());
        equivocation.add(h.confirmations().stream().filter(c -> (c[34] & 0xFF) == 3).findFirst().orElseThrow());
        assertEquals(context, ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE, signed(config, equivocation),
                verifier(config, h.transcriptMessages(), equivocation)));
        // Without participant 3, the equivocator leaves only one matching confirmation: refused.
        List<byte[]> tooFew = equivocation.subList(0, 3);
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE,
                signed(config, tooFew), verifier(config, h.transcriptMessages(), tooFew)));
    }

    @Test
    @DisplayName("t + 1 unauthenticated differing confirmations are ignored, not counted; authenticated, they refuse")
    void unauthenticatedLiesIgnored() {
        DkgConfig config = DkgHarness.config(1, 4, "admission-unauthenticated", 1);
        DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
        ThresholdKeyContext context = h.participant(1).result().context();
        JubjubPoint y = context.jointKey().point();
        byte[] other = new byte[32];
        other[0] = 1;
        List<byte[]> lies = List.of(DkgMessage.confirmation(config, 3, other, y).encode(),
                DkgMessage.confirmation(config, 4, other, y).encode());
        var transcript = signed(config, h.transcriptMessages());
        List<AuthenticatedDkgMessage> submitted = new ArrayList<>(signed(config, h.confirmations()));
        for (byte[] lie : lies) submitted.add(new AuthenticatedDkgMessage(lie, new byte[32])); // forged tags
        // The forged lies are not delivered, so the board's round 7 is the honest confirmations.
        assertEquals(context, ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE, submitted,
                verifier(config, h.transcriptMessages(), h.confirmations())));
        // Control: the same t + 1 lies, authenticated, make 3 and 4 equivocators, so differing.
        List<byte[]> board = new ArrayList<>(h.confirmations());
        board.addAll(lies);
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE,
                signed(config, board), verifier(config, h.transcriptMessages(), board)));
    }

    @Test
    @DisplayName("Round-7 closure covers confirmations from outside QUAL: they are ignored in the count but cannot be left out")
    void roundSevenIncludesNonQualified() {
        DkgConfig config = DkgHarness.config(1, 4, "admission-non-qual", 1);
        DkgHarness h = DkgHarness.random(config, (m, honest) ->
                m.kind() == DkgMessage.Kind.COMMITMENTS && m.sender() == 3 ? List.of() : honest).run();
        assertEquals(FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED, h.aborted.get(3).reason());
        ThresholdKeyContext context = h.participant(1).result().context();
        assertEquals(Set.of(1, 2, 4), context.qual());
        // Participant 3 (not in QUAL) posts an authenticated confirmation anyway.
        byte[] outsider = DkgMessage.confirmation(config, 3, context.transcriptDigest(), context.jointKey().point()).encode();
        List<byte[]> board = new ArrayList<>(h.confirmations());
        board.add(outsider);
        var transcript = signed(config, h.transcriptMessages());
        assertEquals(context, ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE, signed(config, board),
                verifier(config, h.transcriptMessages(), board)));
        // Leaving it out of the submission no longer matches the board's round 7.
        assertThrows(IllegalArgumentException.class, () -> ThresholdKeyContext.admit(config, transcript, NO_EVIDENCE,
                signed(config, h.confirmations()), verifier(config, h.transcriptMessages(), board)));
    }

    @Test
    @DisplayName("deliveredRound drops junk posts, so a faulty participant's malformed or stale posts cannot veto closure")
    void deliveredRoundFiltersJunk() {
        DkgConfig config = DkgHarness.config(1, 3, "admission-junk", 1);
        DkgHarness h = DkgHarness.random(config, DkgHarness.HONEST).run();
        DkgConfig stale = DkgHarness.config(1, 3, "admission-junk", 2);
        List<AuthenticatedDkgMessage> raw = new ArrayList<>(signed(config, h.transcriptMessages()));
        raw.add(new AuthenticatedDkgMessage(new byte[5], new byte[32]));                 // malformed
        byte[] foreign = DkgMessage.complaint(stale, 3, 1).encode();
        raw.add(new AuthenticatedDkgMessage(foreign, tag(config.rosterKey(3), foreign)));   // other session
        byte[] unauthenticated = DkgMessage.complaint(config, 3, 1).encode();
        raw.add(new AuthenticatedDkgMessage(unauthenticated, new byte[32]));             // bad authenticator
        DkgAdmissionVerifier strict = new DkgAdmissionVerifier() {
            @Override
            public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
                return Arrays.equals(tag(rosterKey, message), authenticator);
            }

            @Override
            public boolean roundClosed(DkgConfig c, int round, List<byte[]> canonicalMessages, byte[] evidence) {
                if (round == 7) return true;
                return sameList(DkgTranscript.deliveredRound(c, round, raw, this), canonicalMessages);
            }
        };
        assertEquals(h.participant(1).result().context(), ThresholdKeyContext.admit(config,
                signed(config, h.transcriptMessages()), NO_EVIDENCE, signed(config, h.confirmations()), strict));
        assertEquals(0, DkgTranscript.deliveredRound(config, 2, raw, strict).size(), "the junk complaint is dropped");
    }
}
