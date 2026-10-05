package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * ADR-0053 M0–M3: the library against the independent {@code elgamal-jubjub-threshold-v1}
 * reference. {@code src/test/resources/elgamal-threshold-reference/reference-output.txt} was
 * produced by a standard-library Python implementation written from the spec, the [GJKR07]
 * Fig. 2 text and the Jubjub definition. No ZeroJ Java source was read.
 *
 * <p>Every fixture is run through the Java {@link DkgParticipant}s and compared value by value:
 * the session, the commitments, the shares, every broadcast message's bytes, the transcript
 * digest, {@code QUAL}, the marks, the aborts, {@code y}, {@code Y_j}, {@code x_j}, the
 * confirmations, the Lagrange coefficients and the threshold decryptions. The adversarial fixture
 * replays the spec's §11 script. Every replayable {@code case.*} vector (abort, rule, finding,
 * admission, combine, parameter and well-formedness cases) is replayed from its keys alone.
 * Regenerate with
 * {@code python3 elgamal_jubjub_threshold_v1_reference.py} in that directory.
 */
class ThresholdReferenceVectorsTest {

    private static final String RESOURCE = "/elgamal-threshold-reference/reference-output.txt";
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static Map<String, String> ref;

    @BeforeAll
    static void load() throws IOException {
        ref = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(
                ThresholdReferenceVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE);
             var reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                ref.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
    }

    private static String get(String key) {
        return Objects.requireNonNull(ref.get(key), () -> "missing reference key " + key);
    }

    private static BigInteger num(String key) {
        String s = get(key);
        return s.startsWith("0x") ? new BigInteger(s.substring(2), 16) : new BigInteger(s);
    }

    private static byte[] bytes(String key) {
        return HEX.parseHex(get(key));
    }

    private static Set<Integer> ids(String key) {
        Set<Integer> out = new TreeSet<>();
        String v = get(key);
        if (v.isEmpty()) return out;
        for (String part : v.split(",")) out.add(Integer.parseInt(part.split(":")[0]));
        return out;
    }

    private static DkgConfig config(String f) {
        int t = num(f + ".t").intValueExact();
        int n = num(f + ".n").intValueExact();
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= n; j++) {
            byte[] key = new byte[32];
            Arrays.fill(key, (byte) j);
            roster.add(key);
        }
        return DkgConfig.create(t, n, roster, bytes(f + ".ctx"), num(f + ".attempt").longValueExact());
    }

    private static List<ThresholdVss.Dealing> dealings(String f, int t, int n) {
        List<ThresholdVss.Dealing> out = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            BigInteger[] a = new BigInteger[t + 1];
            BigInteger[] b = new BigInteger[t + 1];
            for (int k = 0; k <= t; k++) {
                a[k] = num(f + ".a." + i + "." + k);
                b[k] = num(f + ".b." + i + "." + k);
            }
            ThresholdVss.Dealing d = ThresholdVss.dealWithCoefficients(a, b);
            for (int k = 0; k <= t; k++) {
                assertArrayEquals(bytes(f + ".C." + i + "." + k), d.commitments().get(k).toBytes(), f + " C." + i + "." + k);
                assertArrayEquals(bytes(f + ".A." + i + "." + k), d.extraction().get(k).toBytes(), f + " A." + i + "." + k);
            }
            for (int j = 1; j <= n; j++) {
                assertEquals(num(f + ".s." + i + "." + j), d.share(j), f + " s." + i + "." + j);
                assertEquals(num(f + ".sp." + i + "." + j), d.sharePrime(j), f + " sp." + i + "." + j);
            }
            out.add(d);
        }
        return out;
    }

    private static FaultAssumptionViolatedException.Reason reason(String code) {
        return switch (code) {
            case "A1" -> FaultAssumptionViolatedException.Reason.TOO_FEW_QUALIFIED;
            case "A2" -> FaultAssumptionViolatedException.Reason.OWN_DEALING_DISQUALIFIED;
            case "A3" -> FaultAssumptionViolatedException.Reason.TOO_FEW_RECONSTRUCTION_PAIRS;
            case "A4" -> FaultAssumptionViolatedException.Reason.INCONSISTENT_RECONSTRUCTION;
            case "A5" -> FaultAssumptionViolatedException.Reason.IDENTITY_JOINT_KEY;
            case "A6" -> FaultAssumptionViolatedException.Reason.SHARE_MISMATCH;
            case "A7" -> FaultAssumptionViolatedException.Reason.CONFLICTING_CONFIRMATION;
            case "A8" -> FaultAssumptionViolatedException.Reason.OWN_DEALING_MARKED;
            default -> throw new IllegalArgumentException(code);
        };
    }

    /** The spec §11 adversarial-4of7 script as harness deviations; everything else is §5. */
    private static DkgHarness.Adversary adversarialScript(DkgConfig config) {
        return (m, honest) -> {
            if (m.kind() == DkgMessage.Kind.SHARE && m.sender() == 1 && m.subject() == 2
                    || m.kind() == DkgMessage.Kind.SHARE && m.sender() == 3 && m.subject() == 4) {
                byte[] bad = DkgMessage.pair(config, DkgMessage.Kind.SHARE, m.sender(), m.subject(),
                        m.s().add(BigInteger.ONE).mod(L), m.sPrime()).encode();
                return List.of(new DkgHarness.Delivery(m.sender(), m.subject(), bad));
            }
            if (m.kind() == DkgMessage.Kind.ANSWER && m.sender() == 3) return List.of();
            if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 1) return List.of();
            if (m.kind() == DkgMessage.Kind.EXTRACTION && m.sender() == 5) {
                List<JubjubPoint> forged = new ArrayList<>(m.points());
                forged.set(1, forged.get(1).add(JubjubPoint.SUBGROUP_GENERATOR).normalized());
                byte[] bytes = DkgMessage.points(config, DkgMessage.Kind.EXTRACTION, 5, forged).encode();
                List<DkgHarness.Delivery> out = new ArrayList<>();
                for (DkgHarness.Delivery d : honest) out.add(new DkgHarness.Delivery(5, d.recipient(), bytes));
                return out;
            }
            return honest;
        };
    }

    private static void checkFixture(String f, DkgHarness.Adversary adversary) {
        DkgConfig config = config(f);
        assertArrayEquals(bytes(f + ".session"), config.session(), f + " session");
        assertArrayEquals(bytes("session." + f), config.session());
        List<ThresholdVss.Dealing> dealings = dealings(f, config.t(), config.n());
        DkgHarness h = DkgHarness.fixed(config, dealings, adversary).run();

        // Every broadcast message, byte for byte, and the per-round counts.
        List<byte[]> referenceMessages = new ArrayList<>();
        for (var e : ref.entrySet()) {
            if (e.getKey().startsWith(f + ".msg.")) referenceMessages.add(HEX.parseHex(e.getValue()));
        }
        DkgTranscript ours = DkgTranscript.of(config, h.transcriptMessages());
        DkgTranscript theirs = DkgTranscript.of(config, referenceMessages);
        String[] counts = get(f + ".counts").split(",");
        for (int r = 1; r <= 6; r++) {
            List<byte[]> a = ours.roundMessages(r);
            List<byte[]> b = theirs.roundMessages(r);
            assertEquals(Integer.parseInt(counts[r - 1]), a.size(), f + " round " + r + " count");
            assertEquals(b.size(), a.size(), f + " round " + r);
            for (int i = 0; i < a.size(); i++) assertArrayEquals(b.get(i), a.get(i), f + " round " + r + " message " + i);
        }
        assertArrayEquals(bytes(f + ".digest"), ours.digest(), f + " digest");
        if (ref.containsKey(f + ".transcript")) assertArrayEquals(bytes(f + ".transcript"), ours.encode(), f + " transcript");

        // Public outcome.
        DkgTranscript.DkgPublicOutcome outcome = ours.recompute();
        assertEquals(ids(f + ".qual"), outcome.qual(), f + " QUAL");
        assertEquals(ids(f + ".marked"), outcome.marked(), f + " marked");
        assertArrayEquals(bytes(f + ".y"), outcome.jointKey().toBytes(), f + " y");
        for (int j = 1; j <= config.n(); j++) {
            assertArrayEquals(bytes(f + ".Y." + j), outcome.verificationKeys().get(j - 1).toBytes(), f + " Y." + j);
        }

        // Aborts, secret shares and confirmations.
        for (int j = 1; j <= config.n(); j++) {
            String code = ref.getOrDefault(f + ".participant_abort." + j, "none");
            if (code.equals("none")) {
                assertTrue(!h.aborted.containsKey(j), f + " participant " + j + " aborted: " + h.aborted.get(j));
                ThresholdKeyShare share = h.participant(j).result();
                assertEquals(num(f + ".x." + j), share.secretScalar(), f + " x." + j);
            } else {
                assertEquals(reason(code), h.aborted.get(j).reason(), f + " participant " + j);
            }
        }
        for (byte[] confirmation : h.confirmations()) {
            int sender = confirmation[34] & 0xFF;
            assertArrayEquals(bytes(f + ".confirmation." + sender), confirmation, f + " confirmation " + sender);
        }
    }

    private static void checkDecryption(String f) {
        DkgConfig config = config(f);
        DkgHarness h = DkgHarness.fixed(config, dealings(f, config.t(), config.n()), DkgHarness.HONEST).run();
        List<ThresholdKeyShare> keys = new ArrayList<>();
        for (DkgParticipant p : h.participants) keys.add(p.result());
        ThresholdKeyContext ctx = keys.get(0).context();
        ElGamalCiphertext c = ElGamal.encryptWithRandomness(ctx, num(f + ".enc.m"),
                num(f + ".enc.width").intValueExact(), num("scalar.enc.k"));
        assertArrayEquals(bytes(f + ".enc.A"), c.handle().toBytes(), f + " enc.A");
        assertArrayEquals(bytes(f + ".enc.B"), c.blinded().toBytes(), f + " enc.B");
        List<VerifiedDecryptionShare> shares = new ArrayList<>();
        for (ThresholdKeyShare k : keys) {
            VerifiedDecryptionShare d = ElGamal.decryptionShare(k, c);
            assertArrayEquals(bytes(f + ".D." + k.id()), d.encode(), f + " D." + k.id());
            shares.add(d);
        }
        long m = num(f + ".enc.m").longValueExact();
        long bound = c.bound().longValueExact();
        int subsets = 0;
        for (var e : ref.entrySet()) {
            String prefix = f + ".decrypt.";
            if (!e.getKey().startsWith(prefix) || e.getKey().endsWith(".all")) continue;
            String subset = e.getKey().substring(prefix.length());
            int[] s = Arrays.stream(subset.split("-")).mapToInt(Integer::parseInt).toArray();
            BigInteger[] lambda = ThresholdMath.lagrangeAt(s, 0);
            List<VerifiedDecryptionShare> chosen = new ArrayList<>();
            for (int i = 0; i < s.length; i++) {
                assertEquals(num(f + ".lagrange." + subset + "." + s[i]), lambda[i], f + " lambda " + subset);
                chosen.add(shares.get(s[i] - 1));
            }
            assertEquals(Long.parseLong(e.getValue()), ElGamal.decrypt(c, chosen, bound), f + " subset " + subset);
            assertEquals(m, Long.parseLong(e.getValue()));
            subsets++;
        }
        assertTrue(subsets > 0, f + " has subsets");
        assertEquals(num(f + ".decrypt.all").longValueExact(), ElGamal.decrypt(c, shares, bound));
    }

    @Test
    @DisplayName("The reference run passed its own checks and matched every spec pin")
    void referenceRunPassed() {
        assertEquals("elgamal-jubjub-threshold-v1", get("profile"));
        assertEquals("pass", get("result"));
        int checks = 0;
        for (var e : ref.entrySet()) {
            String k = e.getKey();
            if (k.startsWith("check.") || k.startsWith("spec_match.") || k.contains(".check.")) {
                assertEquals("true", e.getValue(), k);
                checks++;
            }
        }
        assertTrue(checks > 300, "checks: " + checks);
        assertArrayEquals(bytes("G.encoding"), JubjubPoint.SUBGROUP_GENERATOR.toBytes());
        assertArrayEquals(bytes("H.encoding"), PedersenCommitment.H.toBytes());
    }

    @Test
    @DisplayName("Session ids, BLAKE2b and the test-scalar derivation")
    void sessionAndScalars() throws NoSuchAlgorithmException {
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= 3; j++) {
            byte[] key = new byte[32];
            Arrays.fill(key, (byte) j);
            roster.add(key);
        }
        DkgConfig c = DkgConfig.create(1, 3, roster, "zeroj.test.election".getBytes(StandardCharsets.UTF_8), 1);
        assertArrayEquals(bytes("session.session"), c.session());
        int scalars = 0;
        for (var e : ref.entrySet()) {
            if (!e.getKey().startsWith("scalar.")) continue;
            String tag = e.getKey().substring("scalar.".length());
            byte[] h = MessageDigest.getInstance("SHA-256")
                    .digest(("zeroj.elgamal.threshold.v1.test." + tag).getBytes(StandardCharsets.UTF_8));
            assertEquals(num(e.getKey()), new BigInteger(1, h).mod(L), tag);
            scalars++;
        }
        assertTrue(scalars >= 56, "scalars: " + scalars);
    }

    @Test
    @DisplayName("Honest 2-of-3, 3-of-5 and 4-of-7: participants, transcript, outputs and every subset's decryption")
    void honest() {
        for (String f : List.of("honest-2of3", "honest-3of5", "honest-4of7")) {
            checkFixture(f, DkgHarness.HONEST);
            checkDecryption(f);
        }
    }

    @Test
    @DisplayName("F7 fixtures: zero share (Y_1 = O) and equal shares, through the safe context")
    void f7() {
        for (String f : List.of("zero-share", "equal-shares")) {
            checkFixture(f, DkgHarness.HONEST);
            checkDecryption(f);
        }
        assertEquals("true", get("zero-share.Y.1.identity"));
    }

    @Test
    @DisplayName("Adversarial 4-of-7: the §11 script reproduces every message, abort and output")
    void adversarial() {
        checkFixture("adversarial-4of7", adversarialScript(config("adversarial-4of7")));
        assertEquals("true", get("adversarial-4of7.y_equals_reference"));
    }

    // ---------------------------------------------------------------- case.* vectors

    private static final List<String> FIXTURES =
            List.of("honest-2of3", "honest-3of5", "honest-4of7", "zero-share", "equal-shares", "adversarial-4of7");
    private static final Map<String, DkgHarness> FIXTURE_RUNS = new HashMap<>();

    /** Authenticates every post: the delivered sets of {@code raw.*} posts. */
    private static final DkgAdmissionVerifier TRUSTING = new DkgAdmissionVerifier() {
        @Override
        public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
            return true;
        }

        @Override
        public boolean roundClosed(DkgConfig config, int round, List<byte[]> canonicalMessages, byte[] evidence) {
            return true;
        }
    };

    /** One {@code case.<family>.<name>.*} vector: its keys with that prefix removed. */
    private record Case(String name, Map<String, String> keys) {
        boolean has(String key) {
            return keys.containsKey(key);
        }

        boolean hasPrefix(String prefix) {
            return keys.keySet().stream().anyMatch(k -> k.startsWith(prefix));
        }

        String get(String key) {
            return Objects.requireNonNull(keys.get(key), () -> name + ": missing " + key);
        }

        /** {@code prefix1, prefix2, …}, which must be numbered without gaps. */
        List<byte[]> list(String prefix) {
            List<byte[]> out = new ArrayList<>();
            for (int i = 1; keys.containsKey(prefix + i); i++) out.add(HEX.parseHex(keys.get(prefix + i)));
            long numbered = keys.keySet().stream()
                    .filter(k -> k.startsWith(prefix) && k.substring(prefix.length()).matches("\\d+")).count();
            assertEquals(numbered, out.size(), name + ": " + prefix + "* is not numbered 1..k");
            return out;
        }
    }

    private static Map<String, Case> cases() {
        Map<String, Map<String, String>> grouped = new TreeMap<>();
        for (var e : ref.entrySet()) {
            String k = e.getKey();
            if (!k.startsWith("case.")) continue;
            int familyEnd = k.indexOf('.', "case.".length());
            int nameEnd = k.indexOf('.', familyEnd + 1);
            grouped.computeIfAbsent(k.substring("case.".length(), nameEnd), x -> new LinkedHashMap<>())
                    .put(k.substring(nameEnd + 1), e.getValue());
        }
        Map<String, Case> out = new TreeMap<>();
        grouped.forEach((name, keys) -> out.put(name, new Case(name, keys)));
        return out;
    }

    /** A parsed {@code config} and roster, not yet validated by the library. */
    private record ConfigInput(int t, int n, List<byte[]> roster, byte[] context, BigInteger attempt) {
        /** The API takes the unsigned 64-bit attempt as a {@code long}. */
        boolean attemptExpressible() {
            return attempt.signum() >= 0 && attempt.bitLength() <= 64;
        }

        DkgConfig create() {
            assertTrue(attemptExpressible(), "attempt " + attempt + " cannot be passed to the API");
            return DkgConfig.create(t, n, roster, context, attempt.longValue());
        }
    }

    /**
     * {@code t,n,ctx-hex,attempt}. The roster is {@code standard} ({@code key_j} = 32 bytes of
     * {@code j}), {@code lengths:} (each {@code key_j} = bytes of {@code j} at that length) or
     * {@code hex:} (explicit keys). Parsing errors fail the test; they never count as a rejection.
     */
    private static ConfigInput configInput(Case c) {
        String[] f = c.get("config").split(",", -1);
        assertEquals(4, f.length, c.name() + " config");
        int n = Integer.parseInt(f[1]);
        String roster = c.keys().getOrDefault("roster", "standard");
        List<byte[]> keys = new ArrayList<>();
        if (roster.startsWith("hex:")) {
            for (String key : roster.substring("hex:".length()).split(",", -1)) keys.add(HEX.parseHex(key));
        } else {
            String[] lengths = roster.equals("standard") ? null : roster.substring("lengths:".length()).split(",");
            assertTrue(lengths == null || lengths.length == n, c.name() + " roster");
            for (int j = 1; j <= n; j++) {
                byte[] key = new byte[lengths == null ? 32 : Integer.parseInt(lengths[j - 1])];
                Arrays.fill(key, (byte) j);
                keys.add(key);
            }
        }
        return new ConfigInput(Integer.parseInt(f[0]), n, keys, HEX.parseHex(f[2]), new BigInteger(f[3]));
    }

    private static DkgConfig caseConfig(Case c) {
        return configInput(c).create();
    }

    private static Set<Integer> idSet(String value) {
        Set<Integer> out = new TreeSet<>();
        if (!value.isEmpty()) for (String part : value.split(",")) out.add(Integer.parseInt(part));
        return out;
    }

    private static List<AuthenticatedDkgMessage> authenticated(List<byte[]> messages) {
        List<AuthenticatedDkgMessage> out = new ArrayList<>();
        for (byte[] m : messages) out.add(new AuthenticatedDkgMessage(m, new byte[0]));
        return out;
    }

    private static boolean sameBytes(List<byte[]> a, List<byte[]> b) {
        if (a.size() != b.size()) return false;
        for (int i = 0; i < a.size(); i++) if (!Arrays.equals(a.get(i), b.get(i))) return false;
        return true;
    }

    @TestFactory
    @DisplayName("Every replayable case vector reaches the reference's outcome")
    Stream<DynamicTest> caseVectors() {
        Map<String, Case> cases = cases();
        assertEquals(num("info.case_count").intValueExact(), cases.size(), "case count");
        return cases.values().stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> replay(c)));
    }

    private static void replay(Case c) {
        if (c.has("params")) {
            replayParameters(c);
        } else if (c.has("decode")) {
            replayDecode(c);
        } else if (c.has("ciphertext")) {
            replayCombine(c);
        } else if (c.get("expect").equals("admit") || c.get("expect").equals("refuse")) {
            replayAdmission(c);
        } else {
            replayRecomputation(c);
        }
    }

    /** {@code rule.param_*}: spec §1 bounds, and the derived session of every accepted one. */
    private static void replayParameters(Case c) {
        ConfigInput input = configInput(c);
        switch (c.get("params")) {
            case "accept" -> assertArrayEquals(HEX.parseHex(c.get("session")), input.create().session(), c.name() + " session");
            case "reject" -> {
                if (!input.attemptExpressible()) return; // refused by the API's type, as the spec's u64 requires
                assertThrows(IllegalArgumentException.class, () -> DkgConfig.create(input.t(), input.n(),
                        input.roster(), input.context(), input.attempt().longValue()), c.name());
            }
            default -> fail(c.name() + ": unknown params " + c.get("params"));
        }
    }

    /** {@code wf.*}: §4 well-formedness of the single message {@code msg.1}. */
    private static void replayDecode(Case c) {
        DkgConfig config = caseConfig(c);
        List<byte[]> messages = c.list("msg.");
        assertEquals(1, messages.size(), c.name());
        byte[] m = messages.get(0);
        switch (c.get("decode")) {
            case "accept" -> assertArrayEquals(m, DkgMessage.decode(config, m).encode(), c.name() + " re-encodes");
            case "reject" -> assertThrows(IllegalArgumentException.class, () -> DkgMessage.decode(config, m), c.name());
            default -> fail(c.name() + ": unknown decode " + c.get("decode"));
        }
    }

    /**
     * Abort, rule and finding cases: the public recomputation of the case transcript. The posts
     * {@code raw.*}, where given, must give the same delivered sets.
     */
    private static void replayRecomputation(Case c) {
        DkgConfig config = caseConfig(c);
        String expect = c.get("expect");
        List<byte[]> messages = c.list("msg.");
        assertFalse(messages.isEmpty(), c.name() + ": a recomputation case needs its transcript");
        if (c.has("H")) {
            replayTrapdoor(c, config, messages);
            return;
        }
        DkgTranscript transcript = DkgTranscript.of(config, messages);
        List<byte[]> canonical = new ArrayList<>();
        for (int r = 1; r <= 6; r++) canonical.addAll(transcript.roundMessages(r));
        assertTrue(sameBytes(messages, canonical), c.name() + ": msg.* is not in Java's §6 order");
        List<byte[]> raw = c.list("raw.");
        if (!raw.isEmpty()) {
            List<AuthenticatedDkgMessage> posts = authenticated(raw);
            for (int r = 1; r <= 6; r++) {
                assertTrue(sameBytes(transcript.roundMessages(r), DkgTranscript.deliveredRound(config, r, posts, TRUSTING)),
                        c.name() + ": raw posts give another delivered set in round " + r);
            }
        }
        if (expect.startsWith("abort=")) {
            FaultAssumptionViolatedException e =
                    assertThrows(FaultAssumptionViolatedException.class, transcript::recompute, c.name());
            assertEquals(reason(expect.substring("abort=".length())), e.reason(), c.name());
            return;
        }
        Map<String, String> fields = new HashMap<>();
        for (String part : expect.split(";", -1)) {
            int eq = part.indexOf('=');
            fields.put(part.substring(0, eq), part.substring(eq + 1));
        }
        DkgTranscript.DkgPublicOutcome outcome = transcript.recompute();
        assertEquals(idSet(fields.get("qual")), outcome.qual(), c.name() + " QUAL");
        assertEquals(idSet(fields.get("marked")), outcome.marked(), c.name() + " marked");
        assertArrayEquals(HEX.parseHex(fields.get("y")), outcome.jointKey().toBytes(), c.name() + " y");
    }

    /**
     * The A4 trapdoor vectors use a reference-only base {@code H' = [w]·G}, under which a pair off
     * the dealer's polynomial still satisfies (4); the profile's {@code H} cannot be swapped out.
     * The (4) filter is therefore applied here, in test code and under {@code H'}. The library's
     * reconstruction must then refuse with A4 on its check that every valid pair lies on the
     * interpolated polynomial, which does not involve {@code H}.
     */
    private static void replayTrapdoor(Case c, DkgConfig config, List<byte[]> messages) {
        assertEquals("abort=A4", c.get("expect"), c.name());
        FastJubjubPoint hPrime = FastJubjubPoint.of(JubjubPoint.fromBytes(HEX.parseHex(c.get("H"))));
        assertFalse(hPrime.projectiveEquals(FastJubjubPoint.of(PedersenCommitment.H)), c.name());
        Map<Integer, List<JubjubPoint>> commitments = new HashMap<>();
        Map<Integer, Map<Integer, List<BigInteger[]>>> pairs = new TreeMap<>();
        for (byte[] bytes : messages) {
            DkgMessage m = DkgMessage.decode(config, bytes);
            if (m.kind() == DkgMessage.Kind.COMMITMENTS) {
                assertTrue(commitments.put(m.sender(), m.points()) == null, c.name() + ": conflicting commitments");
            } else if (m.kind() == DkgMessage.Kind.RECONSTRUCTION) {
                pairs.computeIfAbsent(m.subject(), x -> new TreeMap<>())
                        .computeIfAbsent(m.sender(), x -> new ArrayList<>()).add(new BigInteger[]{m.s(), m.sPrime()});
            }
        }
        assertFalse(pairs.isEmpty(), c.name() + ": no reconstruction");
        int refused = 0;
        for (var dealer : pairs.entrySet()) {
            List<JubjubPoint> cs = commitments.get(dealer.getKey());
            TreeMap<Integer, BigInteger[]> valid = new TreeMap<>();
            for (var holder : dealer.getValue().entrySet()) {
                if (holder.getValue().size() != 1) continue; // conflicting pairs are excluded (R6)
                BigInteger[] pair = holder.getValue().get(0);
                FastJubjubPoint left = FastJubjubPoint.GENERATOR.scalarMulPublic(pair[0])
                        .add(hPrime.scalarMulPublic(pair[1]));
                FastJubjubPoint right = FastJubjubPoint.IDENTITY;
                for (int k = 0; k < cs.size(); k++) {
                    right = right.add(FastJubjubPoint.of(cs.get(k))
                            .scalarMulPublic(BigInteger.valueOf(holder.getKey()).pow(k).mod(L)));
                }
                if (left.projectiveEquals(right)) valid.put(holder.getKey(), pair);
            }
            try {
                ThresholdVss.reconstruct(cs, config.t(), valid);
            } catch (FaultAssumptionViolatedException e) {
                assertEquals(FaultAssumptionViolatedException.Reason.INCONSISTENT_RECONSTRUCTION, e.reason(), c.name());
                assertTrue(e.getMessage().contains("not on the reconstructed polynomial"), c.name() + ": " + e.getMessage());
                refused++;
            }
        }
        assertTrue(refused > 0, c.name() + ": every reconstruction succeeded");
    }

    /**
     * Admission cases (§8). The verifier is modelled from the keys alone:
     * {@code authenticate} fails exactly for the {@code unauthenticated.*} bytes, and, when the
     * case gives a board ({@code board.<r>.*}), {@code roundClosed} holds iff the presented list
     * is that board's delivered set. Without a board, closure holds, as in the reference. A
     * refusal must also happen at the case's {@code step}.
     */
    private static void replayAdmission(Case c) {
        DkgConfig config = caseConfig(c);
        List<byte[]> messages = c.list("msg.");
        List<AuthenticatedDkgMessage> transcript = authenticated(messages);
        List<AuthenticatedDkgMessage> confirmations = authenticated(c.list("confirmation."));
        List<byte[]> unauthenticated = c.list("unauthenticated.");
        boolean boardModelled = c.hasPrefix("board.");
        assertEquals(boardModelled, c.has("closure"), c.name() + ": closure key and board.* disagree");
        if (boardModelled) assertEquals("board", c.get("closure"), c.name());
        Map<Integer, List<AuthenticatedDkgMessage>> board = new HashMap<>();
        for (int r = 1; r <= 7; r++) board.put(r, authenticated(c.list("board." + r + ".")));
        List<Integer> authenticated = new ArrayList<>();
        List<Integer> closed = new ArrayList<>();
        DkgAdmissionVerifier verifier = new DkgAdmissionVerifier() {
            @Override
            public boolean authenticate(int sender, byte[] rosterKey, byte[] message, byte[] authenticator) {
                assertArrayEquals(config.rosterKey(sender), rosterKey, c.name() + ": roster key of the header's sender");
                authenticated.add(sender);
                return unauthenticated.stream().noneMatch(u -> Arrays.equals(u, message));
            }

            @Override
            public boolean roundClosed(DkgConfig cfg, int round, List<byte[]> canonicalMessages, byte[] evidence) {
                closed.add(round);
                return !boardModelled
                        || sameBytes(canonicalMessages, DkgTranscript.deliveredRound(cfg, round, board.get(round), this));
            }
        };
        Map<Integer, byte[]> closure = new HashMap<>();
        for (int r = 1; r <= 7; r++) closure.put(r, new byte[0]);
        switch (c.get("expect")) {
            case "admit" -> {
                ThresholdKeyContext.admit(config, transcript, closure, confirmations, verifier);
                assertEquals(List.of(1, 2, 3, 4, 5, 6, 7), closed, c.name() + ": closure asked for every round");
            }
            case "refuse" -> {
                RuntimeException e = assertThrows(RuntimeException.class,
                        () -> ThresholdKeyContext.admit(config, transcript, closure, confirmations, verifier), c.name());
                int step = Integer.parseInt(c.get("step"));
                String at = c.name() + " (step " + step + "): " + e;
                assertEquals(step == 5, e instanceof FaultAssumptionViolatedException, at);
                assertTrue(e instanceof IllegalArgumentException || e instanceof FaultAssumptionViolatedException, at);
                if (step >= 3) {
                    DkgTranscript.of(config, messages); // well-formed: the refusal came later than step 2
                    assertFalse(authenticated.isEmpty(), at + ": refused without authenticating");
                }
                switch (step) {
                    case 2 -> {
                        assertThrows(IllegalArgumentException.class, () -> DkgTranscript.of(config, messages), at);
                        assertTrue(authenticated.isEmpty() && closed.isEmpty(), at + ": refused after step 2");
                    }
                    case 3 -> assertTrue(closed.isEmpty(), at + ": closure asked before authentication refused");
                    case 4, 5 -> assertTrue(!closed.isEmpty() && !closed.contains(7), at + ": refused outside steps 4-5");
                    case 6 -> {
                        assertTrue(closed.contains(7), at + ": refused before step 6");
                        DkgTranscript.of(config, messages).recompute();
                    }
                    default -> fail(at + ": unknown step");
                }
            }
            default -> fail(c.name() + ": unknown expect");
        }
    }

    /** The fixture run whose configuration and {@code QUAL} a combine case was built on. */
    private static DkgHarness fixtureRun(DkgConfig config, Set<Integer> qual) {
        DkgHarness match = null;
        for (String f : FIXTURES) {
            if (!config(f).equals(config)) continue;
            DkgHarness h = FIXTURE_RUNS.computeIfAbsent(f, x -> DkgHarness.fixed(config(x),
                    dealings(x, config.t(), config.n()),
                    x.equals("adversarial-4of7") ? adversarialScript(config(x)) : DkgHarness.HONEST).run());
            if (ids(f + ".qual").equals(qual)) {
                assertTrue(match == null, "two fixtures match");
                match = h;
            }
        }
        return Objects.requireNonNull(match, "no fixture has this configuration and QUAL");
    }

    /**
     * Combine cases (§9): the shares are taken as DLEQ-verified, so the library's own checks, the
     * {@code QUAL} membership, the share count and the extra-share consistency, must decide.
     * {@code not_plaintext:<m>} is an unverified bad share among the first {@code t + 1}: no check
     * can see it, and the result must not be {@code m}.
     */
    private static void replayCombine(Case c) {
        DkgConfig config = caseConfig(c);
        Set<Integer> qual = idSet(c.get("qual"));
        DkgHarness h = fixtureRun(config, qual);
        ThresholdKeyShare anyKey = null;
        for (DkgParticipant p : h.participants) {
            if (!h.aborted.containsKey(p.id())) {
                anyKey = p.result();
                break;
            }
        }
        ThresholdKeyContext context = Objects.requireNonNull(anyKey).context();
        assertEquals(qual, context.qual(), c.name() + " QUAL");
        BigInteger bound = new BigInteger(c.get("bound"));
        int width = bound.bitLength();
        assertEquals(BigInteger.ONE.shiftLeft(width).subtract(BigInteger.ONE), bound, c.name() + ": bound is 2^w - 1");
        ElGamalCiphertext ct = ElGamal.admit(
                RawElGamalCiphertext.decode(HEX.parseHex(c.get("ciphertext"))), context, width, s -> true);
        Map<Integer, byte[]> submitted = new TreeMap<>();
        for (var e : c.keys().entrySet()) {
            if (e.getKey().startsWith("share.")) {
                submitted.put(Integer.parseInt(e.getKey().substring("share.".length())), HEX.parseHex(e.getValue()));
            }
        }
        String expect = c.get("expect");
        if (expect.startsWith("plaintext:")) {
            List<VerifiedDecryptionShare> shares = new ArrayList<>();
            for (var e : submitted.entrySet()) {
                VerifiedDecryptionShare ours = ElGamal.decryptionShare(h.participant(e.getKey()).result(), ct);
                assertArrayEquals(ours.encode(), e.getValue(), c.name() + " D." + e.getKey());
                shares.add(VerifiedDecryptionShare.verify(ct, e.getKey(), e.getValue(), s -> true));
            }
            assertEquals(Long.parseLong(expect.substring("plaintext:".length())),
                    ElGamal.decrypt(ct, shares, bound.longValueExact()), c.name());
            return;
        }
        Supplier<Long> combine = () -> {
            List<VerifiedDecryptionShare> shares = new ArrayList<>();
            for (var s : submitted.entrySet()) shares.add(VerifiedDecryptionShare.verify(ct, s.getKey(), s.getValue(), d -> true));
            return ElGamal.decrypt(ct, shares, bound.longValueExact());
        };
        if (expect.startsWith("not_plaintext:")) {
            long forbidden = Long.parseLong(expect.substring("not_plaintext:".length()));
            try {
                assertNotEquals(forbidden, combine.get(), c.name());
            } catch (ElGamalDecryptionException noMatch) {
                // also not the forbidden value
            }
            return;
        }
        assertEquals("error", expect, c.name());
        RuntimeException e = assertThrows(RuntimeException.class, combine::get, c.name());
        // IllegalArgumentException: refused share set; IllegalStateException: an extra share
        // disagrees with the interpolation (ElGamal.decrypt's documented contract).
        assertTrue(e instanceof IllegalArgumentException || e instanceof IllegalStateException, c.name() + ": " + e);
    }
}
