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
import java.security.SecureRandom;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0054 M0/M2: the library against the independent {@code dkg-share-delivery-hpke-v1}
 * reference ({@code src/test/resources/dkg-share-delivery-reference/}), written from the spec and
 * RFC 9180 with no ZeroJ Java read. Every replayable {@code case.*} vector is replayed through the
 * production code: the codec, {@link DkgShareDelivery#start} and {@link DkgShareDelivery#closeRound1}
 * with a real {@link DkgParticipant}, and the key directory. Regenerate with
 * {@code python3 dkg_share_delivery_hpke_v1_reference.py} in that directory.
 */
class DkgShareDeliveryReferenceVectorsTest {

    private static final String RESOURCE = "/dkg-share-delivery-reference/reference-output.txt";
    private static final String THRESHOLD = "/elgamal-threshold-reference/reference-output.txt";
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static Map<String, String> ref;
    private static Map<String, String> threshold;

    @BeforeAll
    static void load() throws IOException {
        ref = read(RESOURCE);
        threshold = read(THRESHOLD);
    }

    private static Map<String, String> read(String resource) throws IOException {
        Map<String, String> out = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(DkgShareDeliveryReferenceVectorsTest.class.getResourceAsStream(resource), resource);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                out.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
        return out;
    }

    /** The keys of one case, with the {@code case.<family>.<name>.} prefix removed. */
    private record Case(String name, Map<String, String> keys) {
        String get(String k) {
            return Objects.requireNonNull(keys.get(k), () -> name + ": missing " + k);
        }

        boolean has(String k) {
            return keys.containsKey(k);
        }
    }

    /** Cases of a family; a case is the longest key prefix that owns a {@code config} key. */
    private static Map<String, Case> cases(String family, int unused) {
        String prefix = "case." + family + ".";
        Set<String> names = new TreeSet<>();
        for (String k : ref.keySet()) {
            if (k.startsWith(prefix) && k.endsWith(".config")) names.add(k.substring(prefix.length(), k.length() - ".config".length()));
        }
        Map<String, Map<String, String>> grouped = new TreeMap<>();
        for (var e : ref.entrySet()) {
            if (!e.getKey().startsWith(prefix)) continue;
            String rest = e.getKey().substring(prefix.length());
            String owner = null;
            for (String n : names) if (rest.startsWith(n + ".") && (owner == null || n.length() > owner.length())) owner = n;
            if (owner == null) continue;
            grouped.computeIfAbsent(owner, x -> new LinkedHashMap<>()).put(rest.substring(owner.length() + 1), e.getValue());
        }
        Map<String, Case> out = new TreeMap<>();
        grouped.forEach((n, k) -> out.put(n, new Case(family + "." + n, k)));
        return out;
    }

    private static DkgConfig config(String spec) {
        String[] f = spec.split(",", -1);
        int t = Integer.parseInt(f[0]);
        int n = Integer.parseInt(f[1]);
        List<byte[]> roster = new ArrayList<>();
        for (int j = 1; j <= n; j++) {
            byte[] key = new byte[32];
            Arrays.fill(key, (byte) j);
            roster.add(key);
        }
        return DkgConfig.create(t, n, roster, HEX.parseHex(f[2]), Long.parseLong(f[3]));
    }

    /** The threshold reference's fixture dealings, {@code a_ik} and {@code b_ik}. */
    private static List<ThresholdVss.Dealing> fixtureDealings(String fixture, int t, int n) {
        List<ThresholdVss.Dealing> out = new ArrayList<>();
        for (int i = 1; i <= n; i++) {
            BigInteger[] a = new BigInteger[t + 1];
            BigInteger[] b = new BigInteger[t + 1];
            for (int k = 0; k <= t; k++) {
                a[k] = num(threshold.get(fixture + ".a." + i + "." + k));
                b[k] = num(threshold.get(fixture + ".b." + i + "." + k));
            }
            out.add(ThresholdVss.dealWithCoefficients(a, b));
        }
        return out;
    }

    private static BigInteger num(String s) {
        Objects.requireNonNull(s, "threshold fixture value");
        return s.startsWith("0x") ? new BigInteger(s.substring(2), 16) : new BigInteger(s);
    }

    private static String fixtureFor(DkgConfig config) {
        return "honest-" + (config.t() + 1) + "of" + config.n();
    }

    private static AuthenticatedDkgMessage post(DkgConfig config, String auth, byte[] bytes) {
        if ("none".equals(auth)) return new AuthenticatedDkgMessage(bytes, new byte[32]);
        int author = Integer.parseInt(auth);
        return new AuthenticatedDkgMessage(bytes, DkgEncryptedHarness.tag(config.rosterKey(author), bytes));
    }

    private static Set<Integer> ids(String csv) {
        Set<Integer> out = new TreeSet<>();
        if (!csv.isEmpty()) for (String p : csv.split(",")) out.add(Integer.parseInt(p.trim()));
        return out;
    }

    private static Set<String> pairs(String csv) {
        Set<String> out = new TreeSet<>();
        if (!csv.isEmpty()) out.addAll(Arrays.asList(csv.split(",")));
        return out;
    }

    // ---------------------------------------------------------------- self-check

    @Test
    @DisplayName("The reference run passed its own checks, including RFC 9180 A.2.1 and Wycheproof")
    void referencePassed() {
        assertEquals("pass", ref.get("result"));
        int checks = 0;
        for (var e : ref.entrySet()) {
            if (e.getKey().startsWith("check.")) {
                assertEquals("true", e.getValue(), e.getKey());
                checks++;
            }
        }
        assertTrue(checks > 200, "checks: " + checks);
        int cases = 0;
        for (String family : List.of("announce", "envelope", "directory", "timing", "run", "exposure")) cases += cases(family, 1).size();
        assertEquals(Integer.parseInt(ref.get("info.case_count")), cases, "every case vector is replayed");
    }

    // ---------------------------------------------------------------- announce

    @TestFactory
    @DisplayName("case.announce.*: §3.1 well-formedness through the codec")
    Stream<DynamicTest> announce() {
        return cases("announce", 1).values().stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> {
            DkgConfig config = config(c.get("config"));
            boolean accepted = DkgShareDeliveryCodec.decodeAnnouncement(config, HEX.parseHex(c.get("bytes"))) != null;
            assertEquals("accept".equals(c.get("expect")), accepted, c.name());
        }));
    }

    // ---------------------------------------------------------------- envelope

    @TestFactory
    @DisplayName("case.envelope.*: §4.2 acceptance through closeRound1 and a bound participant")
    Stream<DynamicTest> envelope() {
        return cases("envelope", 1).values().stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> {
            DkgConfig config = config(c.get("config"));
            int j = Integer.parseInt(c.get("recipient"));
            DkgShareDeliveryKeys keys = DkgShareDeliveryKeys.fromSecret(config, j, DkgEncryptedHarness.testKey(c.get("recipient_key_tag")));
            DkgKeyDirectory dir = DkgKeyDirectory.fromRound0(config, List.of(post(config, Integer.toString(j), keys.announcement())),
                    DkgEncryptedHarness.AUTH);
            DkgParticipant p = DkgParticipant.withDealing(config, j, fixtureDealings(fixtureFor(config), config.t(), config.n()).get(j - 1));
            DkgShareDelivery.start(p, dir, keys, new SecureRandom());
            List<AuthenticatedDkgMessage> window = new ArrayList<>();
            if (c.has("bytes")) window.add(post(config, c.get("auth"), HEX.parseHex(c.get("bytes"))));
            for (int k = 1; c.has("bytes." + k); k++) window.add(post(config, c.get("auth." + k), HEX.parseHex(c.get("bytes." + k))));
            DkgShareDelivery.closeRound1(p, dir, keys, window, DkgEncryptedHarness.AUTH);
            List<String> got = new ArrayList<>();
            for (int i = 1; i <= config.n(); i++) for (DkgMessage m : p.receivedShares(i)) got.add(HEX.formatHex(m.encode()));
            String expect = c.get("expect");
            if (expect.equals("absent")) {
                assertEquals(List.of(), got, c.name());
            } else if (expect.startsWith("share:")) {
                assertEquals(List.of(expect.substring(6)), got, c.name());
            } else {
                assertEquals(new TreeSet<>(Arrays.asList(expect.substring(7).split(","))), new TreeSet<>(got), c.name());
            }
            if (c.has("ephemeral_tag")) { // the good case, byte for byte
                byte[] pk = keys.publicKey();
                DkgMessage share = DkgMessage.decode(config, HEX.parseHex(c.get("plaintext")));
                assertArrayEquals(HEX.parseHex(c.get("bytes")), DkgShareDelivery.sealOne(config, share.sender(), share.subject(), pk, share,
                        DkgEncryptedHarness.testKey(c.get("ephemeral_tag"))), c.name() + " envelope bytes");
                assertArrayEquals(HEX.parseHex(c.get("info")), DkgShareDeliveryCodec.info(config, share.sender(), share.subject()));
            }
        }));
    }

    // ---------------------------------------------------------------- run

    @TestFactory
    @DisplayName("case.run.*: full encrypted runs reproduce every announcement, envelope and output byte for byte")
    Stream<DynamicTest> run() {
        return cases("run", 1).values().stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> {
            DkgConfig config = config(c.get("config"));
            String fixture = c.name().substring("run.".length());
            String prefix = c.get("recipient_key_tag.1").replace("recipient.1", "");
            DkgEncryptedHarness h = new DkgEncryptedHarness(config, fixtureDealings(fixture, config.t(), config.n()),
                    DkgEncryptedHarness.HONEST, prefix).run();
            for (int j = 1; j <= config.n(); j++) {
                assertArrayEquals(HEX.parseHex(c.get("announce." + j)), h.keys.get(j).announcement(), "announce " + j);
            }
            int envelopes = 0;
            for (Object[] e : h.sealed) {
                assertArrayEquals(HEX.parseHex(c.get("envelope." + e[0] + "." + e[1])), (byte[]) e[2], "envelope " + e[0] + "." + e[1]);
                envelopes++;
            }
            assertEquals(config.n() * (config.n() - 1), envelopes);
            assertTrue(h.aborted.isEmpty(), "aborts " + h.aborted);
            DkgTranscript transcript = DkgTranscript.of(config, h.transcriptMessages());
            assertArrayEquals(HEX.parseHex(c.get("expect.digest")), transcript.digest(), "digest");
            DkgTranscript.DkgPublicOutcome out = transcript.recompute();
            assertEquals(ids(c.get("expect.qual")), out.qual());
            assertArrayEquals(HEX.parseHex(c.get("expect.y")), out.jointKey().toBytes());
            for (int j = 1; j <= config.n(); j++) {
                assertArrayEquals(HEX.parseHex(c.get("expect.Y." + j)), out.verificationKeys().get(j - 1).toBytes(), "Y." + j);
            }
        }));
    }

    // ---------------------------------------------------------------- directory and timing (board replay)

    @TestFactory
    @DisplayName("case.directory.* and case.timing.*: board replay with windows, lags, the barrier and T1")
    Stream<DynamicTest> board() {
        List<Case> all = new ArrayList<>(cases("directory", 1).values());
        all.addAll(cases("timing", 1).values());
        return all.stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> new BoardReplay(c).run()));
    }

    /** One board vector replayed through the library (honest participants) or the documented negative control. */
    private static final class BoardReplay {
        private final Case c;
        private final DkgConfig config;
        private final int cut0;
        private final int cut1;
        private final boolean barrier;
        private final boolean t1Rule;
        private final Set<Integer> corrupted;
        private final Set<Integer> withholdExtraction;
        private final Set<Integer> ignoreT1;
        private final boolean dedupBeforeAuth;
        private final List<String[]> posts = new ArrayList<>(); // time, author, label, hex
        private final Map<Integer, DkgParticipant> participants = new HashMap<>();
        private final Map<Integer, DkgShareDeliveryKeys> keys = new HashMap<>();
        private final Map<Integer, String> outcome = new TreeMap<>();

        BoardReplay(Case c) {
            this.c = c;
            this.config = config(c.get("config"));
            this.cut0 = Integer.parseInt(c.get("cut0"));
            this.cut1 = Integer.parseInt(c.get("cut1"));
            this.barrier = Boolean.parseBoolean(c.keys().getOrDefault("barrier", "true"));
            this.t1Rule = Boolean.parseBoolean(c.keys().getOrDefault("t1_rule", "true"));
            this.corrupted = ids(c.keys().getOrDefault("corrupted", ""));
            this.withholdExtraction = ids(c.keys().getOrDefault("withhold_extraction", ""));
            this.ignoreT1 = ids(c.keys().getOrDefault("t1_ignored_by", ""));
            this.dedupBeforeAuth = Boolean.parseBoolean(c.keys().getOrDefault("dedup_before_auth", "false"));
            for (int k = 1; c.has("post." + k); k++) posts.add(c.get("post." + k).split(",", 4));
            List<ThresholdVss.Dealing> d = fixtureDealings(fixtureFor(config), config.t(), config.n());
            for (int j = 1; j <= config.n(); j++) {
                participants.put(j, DkgParticipant.withDealing(config, j, d.get(j - 1)));
                keys.put(j, DkgShareDeliveryKeys.fromSecret(config, j, DkgEncryptedHarness.testKey(c.get("recipient_key_tag." + j))));
                outcome.put(j, "none");
            }
        }

        private int lag(int j, String label) {
            return Integer.parseInt(c.keys().getOrDefault("lag." + j + "." + label, "0"));
        }

        /** The posts of a window as participant {@code j} has them when it acts. */
        private List<AuthenticatedDkgMessage> window(int from, int to, int j) {
            List<AuthenticatedDkgMessage> out = new ArrayList<>();
            for (String[] p : posts) {
                int time = Integer.parseInt(p[0]);
                if (time < from || time >= to) continue;
                if (!barrier && time + lag(j, p[2]) >= to) continue; // not processed before the cutoff
                out.add(post(config, p[1], HEX.parseHex(p[3])));
            }
            return out;
        }

        void run() {
            // Round 0: every participant's directory (identical under the barrier).
            Map<Integer, DkgKeyDirectory> dirs = new HashMap<>();
            for (int j = 1; j <= config.n(); j++) dirs.put(j, DkgKeyDirectory.fromRound0(config, window(0, cut0, j), DkgEncryptedHarness.AUTH));
            DkgKeyDirectory reference = DkgKeyDirectory.fromRound0(config, window(0, cut0, 0), DkgEncryptedHarness.AUTH);
            for (int j = 1; j <= config.n(); j++) {
                String expect = c.get("expect.directory." + j);
                assertEquals(expect, reference.key(j).map(HEX::formatHex).orElse("none"), c.name() + " directory " + j);
            }

            // Round 1: honest participants through the library; corrupted ones and negative controls unbound.
            Set<Integer> t1 = new TreeSet<>();
            Map<Integer, List<DkgMessage>> outgoing = new HashMap<>();
            for (int j = 1; j <= config.n(); j++) {
                DkgParticipant p = participants.get(j);
                boolean library = barrier && t1Rule && !dedupBeforeAuth && !corrupted.contains(j) && !ignoreT1.contains(j);
                try {
                    if (library) {
                        DkgShareDelivery.start(p, dirs.get(j), keys.get(j), new SecureRandom());
                        outgoing.put(j, DkgShareDelivery.closeRound1(p, dirs.get(j), keys.get(j), window(cut0, cut1, j), DkgEncryptedHarness.AUTH));
                    } else {
                        if (!dirs.get(j).hasKey(j) && t1Rule && !ignoreT1.contains(j)) {
                            throw new FaultAssumptionViolatedException(FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING, "T1");
                        }
                        p.start();
                        outgoing.put(j, closeUnbound(p, window(cut0, cut1, j)));
                    }
                } catch (FaultAssumptionViolatedException e) {
                    if (e.reason() == FaultAssumptionViolatedException.Reason.OWN_KEY_ANNOUNCEMENT_MISSING) t1.add(j);
                    outcome.put(j, code(e.reason()));
                }
            }
            assertEquals(ids(c.get("expect.t1")), t1, c.name() + " T1");

            // Rounds 2–7, with the corrupted participants' extra complaints in round 2.
            List<List<byte[]>> rounds = new ArrayList<>();
            for (int r = 0; r <= 7; r++) rounds.add(new ArrayList<>());
            for (String[] p : posts) {
                int time = Integer.parseInt(p[0]);
                if (time >= cut0 && time < cut1) rounds.get(1).add(HEX.parseHex(p[3]));
            }
            Map<Integer, List<AuthenticatedDkgMessage>> boardRounds = new HashMap<>();
            List<AuthenticatedDkgMessage> r1 = new ArrayList<>();
            for (String[] p : posts) {
                int time = Integer.parseInt(p[0]);
                if (time >= cut0 && time < cut1) r1.add(post(config, p[1], HEX.parseHex(p[3])));
            }
            boardRounds.put(1, r1);
            for (int round = 2; round <= 7; round++) {
                List<AuthenticatedDkgMessage> window = new ArrayList<>();
                for (int j = 1; j <= config.n(); j++) {
                    for (DkgMessage m : outgoing.getOrDefault(j, List.of())) {
                        if (m.kind() == DkgMessage.Kind.EXTRACTION && withholdExtraction.contains(j)) continue; // withheld
                        window.add(post(config, Integer.toString(j), m.encode()));
                    }
                }
                if (round == 2) {
                    for (int k = 1; c.has("extra_complaint." + k); k++) {
                        String[] cd = c.get("extra_complaint." + k).split("->");
                        int from = Integer.parseInt(cd[0]);
                        window.add(post(config, cd[0], DkgMessage.complaint(config, from, Integer.parseInt(cd[1])).encode()));
                    }
                }
                boardRounds.put(round, window);
                outgoing.clear();
                for (int j = 1; j <= config.n(); j++) {
                    if (!"none".equals(outcome.get(j))) continue;
                    DkgParticipant p = participants.get(j);
                    for (AuthenticatedDkgMessage post : window) {
                        try {
                            DkgMessage m = DkgMessage.decode(config, post.message());
                            if (DkgEncryptedHarness.AUTH.authenticate(m.sender(), config.rosterKey(m.sender()), post.message(), post.authenticator())) {
                                p.receiveBroadcast(m.sender(), post.message());
                            }
                        } catch (IllegalArgumentException refused) {
                            // absent
                        }
                    }
                    try {
                        outgoing.put(j, p.closeRound());
                    } catch (FaultAssumptionViolatedException e) {
                        outcome.put(j, code(e.reason()));
                    }
                }
            }

            assertEquals(pairs(c.get("expect.complaints")), arrows(boardRounds.get(2), DkgMessage.Kind.COMPLAINT), c.name() + " complaints");
            assertEquals(pairs(c.get("expect.answers")), arrows(boardRounds.get(3), DkgMessage.Kind.ANSWER), c.name() + " answers");
            Map<Integer, String> expectedAborts = new TreeMap<>();
            for (String jo : c.get("expect.aborts").split(",")) {
                String[] kv = jo.split(":");
                expectedAborts.put(Integer.parseInt(kv[0]), kv[1]);
            }
            for (int j : expectedAborts.keySet()) {
                if (corrupted.contains(j)) continue; // the reference's corrupted behaviour is not honest code's
                assertEquals(expectedAborts.get(j), outcome.get(j), c.name() + " outcome of " + j);
            }
            List<byte[]> transcript = new ArrayList<>();
            for (int r = 1; r <= 6; r++) {
                List<AuthenticatedDkgMessage> posts = boardRounds.get(r);
                if (r == 1 && dedupBeforeAuth) posts = dedupFirst(posts); // the defective view the negative control records
                transcript.addAll(DkgTranscript.deliveredRound(config, r, posts, DkgEncryptedHarness.AUTH));
            }
            String expectDigest = c.get("expect.digest");
            DkgTranscript t = DkgTranscript.of(config, transcript);
            if (!"none".equals(expectDigest)) assertArrayEquals(HEX.parseHex(expectDigest), t.digest(), c.name() + " digest");
            String publicAbort = c.keys().getOrDefault("expect.public_abort", "none");
            if (!"none".equals(publicAbort)) {
                FaultAssumptionViolatedException e = assertThrows(FaultAssumptionViolatedException.class, t::recompute);
                assertEquals(publicAbort, code(e.reason()), c.name() + " public abort");
            } else {
                DkgTranscript.DkgPublicOutcome out = t.recompute();
                assertEquals(ids(c.get("expect.qual")), out.qual(), c.name() + " QUAL");
                if (c.has("expect.marked")) assertEquals(ids(c.get("expect.marked")), out.marked(), c.name() + " marked");
                assertArrayEquals(HEX.parseHex(c.get("expect.y")), out.jointKey().toBytes(), c.name() + " y");
            }
        }

        /** Keeps the first copy of every byte string, before any authentication (the modelled defect). */
        private static List<AuthenticatedDkgMessage> dedupFirst(List<AuthenticatedDkgMessage> posts) {
            Set<String> seen = new TreeSet<>();
            List<AuthenticatedDkgMessage> out = new ArrayList<>();
            for (AuthenticatedDkgMessage p : posts) if (seen.add(HEX.formatHex(p.message()))) out.add(p);
            return out;
        }

        /** A participant outside the library's barrier: opens what it processed, then closes. */
        private List<DkgMessage> closeUnbound(DkgParticipant p, List<AuthenticatedDkgMessage> window) {
            byte[] sk = DkgEncryptedHarness.testKey(c.get("recipient_key_tag." + p.id()));
            Set<String> seen = new TreeSet<>();
            for (AuthenticatedDkgMessage post : window) {
                byte[] bytes = post.message();
                if (dedupBeforeAuth && !seen.add(HEX.formatHex(bytes))) continue; // the defect the negative control models
                DkgShareDeliveryCodec.Envelope env = DkgShareDeliveryCodec.decodeEnvelope(config, bytes);
                try {
                    if (env != null) {
                        if (env.recipient() != p.id()) continue;
                        if (!DkgEncryptedHarness.AUTH.authenticate(env.sender(), config.rosterKey(env.sender()), bytes, post.authenticator())) continue;
                        byte[] pt = Hpke.openBase(env.enc(), sk, DkgShareDeliveryCodec.info(config, env.sender(), env.recipient()), new byte[0], env.ct());
                        p.receivePrivate(env.sender(), pt);
                    } else {
                        DkgMessage m = DkgMessage.decode(config, bytes);
                        if (DkgEncryptedHarness.AUTH.authenticate(m.sender(), config.rosterKey(m.sender()), bytes, post.authenticator())) {
                            p.receiveBroadcast(m.sender(), bytes);
                        }
                    }
                } catch (Hpke.HpkeException | IllegalArgumentException absent) {
                    // absent
                }
            }
            return p.closeRound();
        }

        private Set<String> arrows(List<AuthenticatedDkgMessage> window, DkgMessage.Kind kind) {
            Set<String> out = new TreeSet<>();
            for (byte[] m : DkgTranscript.deliveredRound(config, kind == DkgMessage.Kind.COMPLAINT ? 2 : 3, window, DkgEncryptedHarness.AUTH)) {
                DkgMessage msg = DkgMessage.decode(config, m);
                if (msg.kind() == kind) out.add(kind == DkgMessage.Kind.COMPLAINT ? msg.sender() + "->" + msg.subject() : msg.sender() + "->" + msg.subject());
            }
            return out;
        }
    }

    private static String code(FaultAssumptionViolatedException.Reason r) {
        return switch (r) {
            case TOO_FEW_QUALIFIED -> "A1";
            case OWN_DEALING_DISQUALIFIED -> "A2";
            case TOO_FEW_RECONSTRUCTION_PAIRS -> "A3";
            case INCONSISTENT_RECONSTRUCTION -> "A4";
            case IDENTITY_JOINT_KEY -> "A5";
            case SHARE_MISMATCH -> "A6";
            case CONFLICTING_CONFIRMATION -> "A7";
            case OWN_DEALING_MARKED -> "A8";
            case OWN_COMPLAINT_MISSING -> "A9";
            case OWN_KEY_ANNOUNCEMENT_MISSING -> "T1";
        };
    }

    // ---------------------------------------------------------------- exposure

    @TestFactory
    @DisplayName("case.exposure.*: the §6 counting rule, and reconstruction from envelopes opened by Java HPKE where a run backs the case")
    Stream<DynamicTest> exposure() {
        AtomicInteger runBacked = new AtomicInteger();
        AtomicInteger reconstructions = new AtomicInteger();
        Stream<DynamicTest> perCase = cases("exposure", 1).values().stream().map(c -> DynamicTest.dynamicTest(c.name(), () -> {
            DkgConfig config = config(c.get("config"));
            int n = config.n();
            Set<Integer> leaked = ids(c.get("leaked"));
            Set<Integer> corruptedSet = ids(c.get("corrupted"));
            Set<String> sent = c.has("sent") ? pairs(c.get("sent")) : allPairs(n);
            Set<String> answers = pairs(c.keys().getOrDefault("answers", ""));
            Set<String> published = pairs(c.keys().getOrDefault("published", ""));
            Set<Integer> reconstructed = ids(c.keys().getOrDefault("reconstructed", ""));
            Set<Integer> qual = ids(c.get("qual"));
            boolean allExposed = true;
            for (int dealer = 1; dealer <= n; dealer++) {
                // The counting rule of spec §6, written here from the spec.
                Set<Integer> known = new TreeSet<>();
                if (corruptedSet.contains(dealer) || reconstructed.contains(dealer)) {
                    for (int x = 1; x <= n; x++) known.add(x);
                } else {
                    for (int j = 1; j <= n; j++) {
                        if (j != dealer && (leaked.contains(j) || corruptedSet.contains(j)) && sent.contains(dealer + "->" + j)) known.add(j);
                    }
                    for (String a : answers) if (a.startsWith(dealer + "->")) known.add(Integer.parseInt(a.split("->")[1]));
                    for (String a : published) if (a.startsWith(dealer + "->")) known.add(Integer.parseInt(a.split("->")[1]));
                }
                if (c.has("known." + dealer)) assertEquals(ids(c.get("known." + dealer)), known, c.name() + " known indices of dealer " + dealer);
                boolean exposed = known.size() >= config.t() + 1;
                if (c.has("expect.dealer." + dealer)) {
                    assertEquals(c.get("expect.dealer." + dealer), exposed ? "exposed" : "unexposed", c.name() + " dealer " + dealer);
                }
                if (qual.contains(dealer)) allExposed &= exposed;
            }
            assertEquals(c.get("expect.x"), allExposed ? "exposed" : "unexposed", c.name() + " x");

            // Where a run backs the case: open the actual envelopes with Java HPKE and reconstruct.
            if (!c.has("source") || !c.get("source").startsWith("case.run.")) return;
            runBacked.incrementAndGet();
            String run = c.get("source").substring("case.run.".length());
            Case runCase = cases("run", 1).get(run);
            List<ThresholdVss.Dealing> d = fixtureDealings(run, config.t(), n);
            for (int dealer = 1; dealer <= n; dealer++) {
                if (corruptedSet.contains(dealer) || !qual.contains(dealer)) continue;
                TreeMap<Integer, BigInteger> points = new TreeMap<>();
                for (int j = 1; j <= n; j++) {
                    if (j == dealer || !(leaked.contains(j) || corruptedSet.contains(j)) || !runCase.has("envelope." + dealer + "." + j)) continue;
                    DkgShareDeliveryCodec.Envelope env = DkgShareDeliveryCodec.decodeEnvelope(config, HEX.parseHex(runCase.get("envelope." + dealer + "." + j)));
                    byte[] pt = Hpke.openBase(env.enc(), DkgEncryptedHarness.testKey(runCase.get("recipient_key_tag." + j)),
                            DkgShareDeliveryCodec.info(config, dealer, j), new byte[0], env.ct());
                    points.put(j, DkgMessage.decode(config, pt).s());
                }
                for (String a : answers) {
                    String[] ij = a.split("->");
                    if (Integer.parseInt(ij[0]) == dealer) points.put(Integer.parseInt(ij[1]), d.get(dealer - 1).share(Integer.parseInt(ij[1])));
                }
                if (points.size() >= config.t() + 1) {
                    assertEquals(d.get(dealer - 1).share(0), DkgShareDeliveryTest.interpolateAtZero(points), c.name() + " z_" + dealer);
                    reconstructions.incrementAndGet();
                }
            }
        }));
        // Guards the replay itself (final review X-1): the run-backed block must actually run.
        DynamicTest coverage = DynamicTest.dynamicTest("run-backed exposure cases reach the HPKE reconstruction", () -> {
            assertTrue(runBacked.get() >= 20, "run-backed cases: " + runBacked.get());
            assertTrue(reconstructions.get() >= 1, "dealer reconstructions: " + reconstructions.get());
        });
        return Stream.concat(perCase, Stream.of(coverage));
    }

    private static Set<String> allPairs(int n) {
        Set<String> out = new TreeSet<>();
        for (int i = 1; i <= n; i++) for (int j = 1; j <= n; j++) if (i != j) out.add(i + "->" + j);
        return out;
    }
}
