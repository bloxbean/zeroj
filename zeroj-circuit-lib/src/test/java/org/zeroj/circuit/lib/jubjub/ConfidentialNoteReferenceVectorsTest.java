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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0055 M0/M2: the library against the independent {@code confidential-note-jubjub-v1}
 * reference ({@code src/test/resources/confidential-note-reference/}), written from the spec and
 * the Zcash specification with no Java read. Every replayable {@code case.*} vector is replayed
 * through the production code: sealing byte for byte (through the package-private ephemeral
 * seam), opening and acceptance, reader-key validation, the KDF, the one-use rule, and D3a's
 * public-input order and hash-compressed serialization.
 *
 * <p>Regenerate with {@code python3 confidential_note_jubjub_v1_reference.py} in that directory.
 */
class ConfidentialNoteReferenceVectorsTest {

    private static final String RESOURCE = "/confidential-note-reference/reference-output.txt";
    private static final HexFormat HEX = HexFormat.of();
    private static final BigInteger TWO_32 = BigInteger.ONE.shiftLeft(32);
    private static Map<String, String> ref;
    private static final AtomicInteger REPLAYED = new AtomicInteger();

    @BeforeAll
    static void load() throws IOException {
        ref = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(ConfidentialNoteReferenceVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
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

    private static BigInteger num(String s) {
        return s.startsWith("0x") ? new BigInteger(s.substring(2), 16) : new BigInteger(s);
    }

    private static byte[] hex(String key) {
        return HEX.parseHex(get(key));
    }

    /** Case names of a family: everything between {@code case.<family>.} and {@code .config}. */
    private static List<String> cases(String family) {
        String prefix = "case." + family + ".";
        TreeSet<String> names = new TreeSet<>();
        for (String key : ref.keySet()) {
            if (key.startsWith(prefix) && key.endsWith(".config")) {
                names.add(key.substring(prefix.length(), key.length() - ".config".length()));
            }
        }
        return new ArrayList<>(names);
    }

    private static NoteViewingKey viewingKey(String name) {
        return NoteViewingKey.fromSecret(num(get("key." + name + ".sk")));
    }

    @Test
    @DisplayName("The reference passed every check, and pins the profile, curve and bases")
    void referencePassed() {
        assertEquals("pass", get("result"));
        assertEquals("confidential-note-jubjub-v1", get("profile"));
        long checks = ref.entrySet().stream().filter(e -> e.getKey().startsWith("check.")).peek(e ->
                assertEquals("true", e.getValue(), e.getKey())).count();
        assertTrue(checks >= 300, "checks: " + checks);
        assertEquals(HEX.formatHex(JubjubPoint.SUBGROUP_GENERATOR.toBytes()), get("base.g.encoding"));
        assertEquals(HEX.formatHex(PedersenCommitment.H.toBytes()), get("base.h.encoding"));
        assertEquals(HEX.formatHex(SaplingNoteCrypto.PERSONALIZATION), get("profile.pers"));
    }

    @Test
    @DisplayName("Viewing keys: [sk]·G matches every reference reader key")
    void readerKeys() {
        for (String key : ref.keySet()) {
            if (key.startsWith("key.") && key.endsWith(".sk")) {
                String name = key.substring(4, key.length() - 3);
                assertEquals(get("key." + name + ".pk"), HEX.formatHex(viewingKey(name).readerKey().encode()), name);
            }
        }
    }

    @TestFactory
    @DisplayName("deliver: sealing is byte-identical through the ephemeral seam, and every reader opens its own delivery")
    Stream<DynamicTest> deliver() {
        return cases("deliver").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String p = "case.deliver." + c + ".";
            String[] readers = get(p + "readers").split(",");
            NoteOpening opening = NoteOpening.of(num(get(p + "value")), num(get(p + "blinding")));
            JubjubPoint commitment = opening.commitment().normalized();
            assertEquals(get(p + "commitment"), HEX.formatHex(commitment.toBytes()));
            assertEquals(num(get(p + "commitment_u")), commitment.affineU());
            assertEquals(num(get(p + "commitment_v")), commitment.affineV());
            assertArrayEquals(hex(p + "plaintext"), ConfidentialNotes.plaintext(opening));
            List<NoteReaderKey> keys = new ArrayList<>();
            for (String r : readers) keys.add(viewingKey(r).readerKey());
            List<byte[]> deliveries = ConfidentialNotes.seal(opening, keys, i -> num(get(p + "ephemeral." + i)));
            for (int i = 0; i < readers.length; i++) {
                assertArrayEquals(hex(p + "delivery." + i), deliveries.get(i), "delivery " + i);
                NoteOpening opened = NoteScanner.of(viewingKey(readers[i])).open(deliveries.get(i), commitment).orElseThrow();
                assertEquals(opening.value(), opened.value());
                assertEquals(opening.blinding(), opened.blinding());
            }
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("open: every accept and reject reproduces; rejects at steps 1–2 or on a non-canonical C do no secret work")
    Stream<DynamicTest> open() {
        return cases("open").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String p = "case.open." + c + ".";
            NoteScanner scanner = NoteScanner.of(viewingKey(get(p + "reader")));
            byte[] delivery = hex(p + "delivery");
            BigInteger u = num(get(p + "commitment_u"));
            BigInteger v = num(get(p + "commitment_v"));
            NoteScheduleTest.Counter counter = new NoteScheduleTest.Counter();
            JubjubPoint.installSecretScheduleObserverForTesting(counter);
            Optional<NoteOpening> result;
            try {
                result = scanner.open(delivery, u, v);
            } finally {
                JubjubPoint.clearSecretScheduleObserverForTesting();
            }
            assertEquals(0, counter.publicMultiplications, "no unblinded multiplication on the opening path");
            int step = Integer.parseInt(get(p + "step"));
            if (get(p + "expect").equals("accept")) {
                assertEquals(num(get(p + "value")), result.orElseThrow().value());
                assertEquals(num(get(p + "blinding")), result.orElseThrow().blinding());
                assertEquals(3, counter.schedules.size(), "an acceptance: Agree and commit's two");
            } else {
                assertTrue(result.isEmpty(), "reject at step " + step);
                boolean canonical = u.signum() >= 0 && u.compareTo(JubjubCurve.BASE_FIELD_PRIME) < 0
                        && v.signum() >= 0 && v.compareTo(JubjubCurve.BASE_FIELD_PRIME) < 0;
                if (step <= 2 || !canonical) {
                    assertEquals(0, counter.schedules.size(), "a public reject does no secret work");
                }
            }
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("readerkey: reader-key validity (spec §2.2)")
    Stream<DynamicTest> readerKey() {
        return cases("readerkey").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String p = "case.readerkey." + c + ".";
            byte[] pk = hex(p + "pk");
            if (get(p + "expect").equals("valid")) {
                assertArrayEquals(pk, NoteReaderKey.decode(pk).encode());
            } else {
                assertThrows(IllegalArgumentException.class, () -> NoteReaderKey.decode(pk));
            }
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("reuse: a repeated ephemeral reproduces both deliveries and leaks the plaintext XOR (the one-use rule)")
    Stream<DynamicTest> reuse() {
        return cases("reuse").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String p = "case.reuse." + c + ".";
            NoteReaderKey reader = viewingKey(get(p + "reader")).readerKey();
            BigInteger e = num(get(p + "ephemeral"));
            byte[] d1 = ConfidentialNotes.sealOne(hex(p + "plaintext1"), reader, e);
            byte[] d2 = ConfidentialNotes.sealOne(hex(p + "plaintext2"), reader, e);
            assertArrayEquals(hex(p + "delivery1"), d1);
            assertArrayEquals(hex(p + "delivery2"), d2);
            byte[] xor = new byte[ConfidentialNotes.PLAINTEXT_LENGTH];
            for (int i = 0; i < xor.length; i++) xor[i] = (byte) (d1[32 + i] ^ d2[32 + i]);
            assertArrayEquals(hex(p + "xor"), xor);
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("kdf: personalised BLAKE2b-256 across block boundaries")
    Stream<DynamicTest> kdf() {
        return cases("kdf").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String p = "case.kdf." + c + ".";
            assertArrayEquals(hex(p + "output"), Blake2bDigest.digest(hex(p + "input"), 32, hex(p + "pers")));
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("d3a: limb split, elgamal-jubjub-v1 ciphertexts, spec §8.2 order and §8.3 digest")
    Stream<DynamicTest> d3a() {
        return cases("d3a").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String p = "case.d3a." + c + ".";
            String[] auditors = get(p + "auditors").split(",");
            int notes = Integer.parseInt(get(p + "notes"));
            List<BigInteger> inputs = new ArrayList<>();
            List<NOfNKeyContext> contexts = new ArrayList<>();
            for (int a = 1; a <= auditors.length; a++) {
                ElGamalSecretKey sk = ElGamalSecretKey.of(num(get("elgamal_key." + auditors[a - 1] + ".sk")));
                contexts.add(NOfNKeyContext.singleKey(sk));
                assertEquals(num(get(p + "pk." + a + ".u")), sk.publicKey().affineU());
                assertEquals(num(get(p + "pk." + a + ".v")), sk.publicKey().affineV());
                inputs.add(sk.publicKey().affineU());
                inputs.add(sk.publicKey().affineV());
            }
            List<BigInteger> coordinates = new ArrayList<>();
            for (int o = 1; o <= notes; o++) {
                BigInteger value = num(get(p + "note." + o + ".value"));
                BigInteger[] limbs = {value.mod(TWO_32), value.shiftRight(32)};
                assertEquals(num(get(p + "note." + o + ".limb0")), limbs[0]);
                assertEquals(num(get(p + "note." + o + ".limb1")), limbs[1]);
                for (int a = 1; a <= auditors.length; a++) {
                    for (int j = 0; j <= 1; j++) {
                        ElGamalCiphertext ct = ElGamal.encryptWithRandomness(contexts.get(a - 1), limbs[j], 32,
                                num(get(p + "k." + o + "." + a + "." + j)));
                        List<BigInteger> expected = new ArrayList<>();
                        for (String x : get(p + "ct." + o + "." + a + "." + j).split(",")) expected.add(num(x));
                        assertEquals(expected, ct.publicInputs(), "note " + o + " auditor " + a + " limb " + j);
                        coordinates.addAll(ct.publicInputs());
                    }
                }
            }
            inputs.addAll(coordinates);
            List<BigInteger> expectedInputs = new ArrayList<>();
            for (String x : get(p + "public_inputs").split(",")) expectedInputs.add(num(x));
            assertEquals(expectedInputs, inputs, "spec §8.2 public-input order");

            byte[] bytes = new byte[32 * coordinates.size()];
            for (int i = 0; i < coordinates.size(); i++) {
                System.arraycopy(DkgMessage.i2osp32(coordinates.get(i)), 0, bytes, 32 * i, 32);
            }
            assertArrayEquals(hex(p + "bytes"), bytes, "spec §8.3 serialization");
            byte[] digest = Blake2bDigest.blake2b256(bytes);
            assertArrayEquals(hex(p + "digest"), digest);
            BigInteger hi = new BigInteger(1, Arrays.copyOfRange(digest, 0, 16));
            BigInteger lo = new BigInteger(1, Arrays.copyOfRange(digest, 16, 32));
            assertEquals(num(get(p + "digest_hi")), hi);
            assertEquals(num(get(p + "digest_lo")), lo);
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("d3a_mut: every mutation of order, encoding or digest gives a different digest")
    Stream<DynamicTest> d3aMutations() {
        return cases("d3a_mut").stream().map(c -> DynamicTest.dynamicTest(c, () -> {
            String base = c.substring(0, c.indexOf('.'));
            String p = "case.d3a_mut." + c + ".";
            boolean differs = !get(p + "digest_hi").equals(get("case.d3a." + base + ".digest_hi"))
                    || !get(p + "digest_lo").equals(get("case.d3a." + base + ".digest_lo"));
            assertTrue(differs, c + " must change the digest");
            REPLAYED.incrementAndGet();
        }));
    }

    @TestFactory
    @DisplayName("Coverage: every case vector of the reference was replayed")
    Stream<DynamicTest> coverage() {
        return Stream.of(DynamicTest.dynamicTest("all families", () -> {
            int expected = Integer.parseInt(get("info.case_count"));
            int listed = 0;
            for (String family : List.of("deliver", "open", "readerkey", "reuse", "kdf", "d3a", "d3a_mut")) {
                listed += cases(family).size();
            }
            assertEquals(expected, listed, "every family is replayed by this test");
            assertNotEquals(0, listed);
        }));
    }
}
