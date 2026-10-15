package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0058 M0: the library against the independent {@code pedersen-jubjub-bytes-v1} reference.
 *
 * <p>{@code src/test/resources/pedersen-bytes-reference/reference-output.txt} was produced by a
 * standard-library Python implementation written from {@code docs/specs/pedersen-jubjub-bytes-v1.md},
 * the {@code pedersen-jubjub-v1} spec and RFC 9380 only; no ZeroJ Java source was read. Every
 * intermediate ({@code b0}, {@code b1}, {@code b2}, uniform bytes), every scalar and every
 * commitment below is computed twice, by unrelated code, and compared here. The mutation fixtures
 * prove the vectors distinguish each plausible implementation mistake. Regenerate with
 * {@code python3 -B pedersen_jubjub_bytes_v1_reference.py} in that directory.
 */
class PedersenBytesReferenceVectorsTest {

    private static final String RESOURCE = "/pedersen-bytes-reference/reference-output.txt";
    private static final HexFormat HEX = HexFormat.of();
    private static Map<String, String> ref;

    @BeforeAll
    static void load() throws IOException {
        ref = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(
                PedersenBytesReferenceVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE);
             var reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                int eq = line.indexOf('=');
                ref.put(line.substring(0, eq), line.substring(eq + 1));
            }
        }
    }

    @Test
    @DisplayName("The reference run passed its RFC 9380 K.1 self-checks and every internal check")
    void referenceRunPassed() {
        assertEquals("pedersen-jubjub-bytes-v1", ref.get("profile"));
        assertEquals(PedersenBytesCommitment.PROFILE_ID, ref.get("profile"));
        assertEquals("pass", ref.get("result"));
        long checks = ref.entrySet().stream().filter(e -> e.getKey().startsWith("check_")).peek(e ->
                assertEquals("true", e.getValue(), e.getKey())).count();
        assertTrue(checks >= 60, "expected the full check set, found " + checks);
    }

    @Test
    @DisplayName("Every payload: n, b0, b1, b2, uniform bytes and s match; streams give the same s")
    void hashFixtures() throws IOException {
        List<String> names = payloadNames();
        assertTrue(names.size() >= 27, "payload fixtures: " + names);
        for (String name : names) {
            byte[] payload = payload(name);
            assertEquals(Long.parseLong(ref.get(name + "_n")), payload.length, name + " n");
            byte[][] im = PedersenBytesHash.intermediatesForTesting(payload);
            assertEquals(ref.get(name + "_b0"), HEX.formatHex(im[0]), name + " b0");
            assertEquals(ref.get(name + "_b1"), HEX.formatHex(im[1]), name + " b1");
            assertEquals(ref.get(name + "_b2"), HEX.formatHex(im[2]), name + " b2");
            assertEquals(ref.get(name + "_uniform"), HEX.formatHex(im[3]), name + " uniform");
            BigInteger s = scalar(name + "_s");
            assertEquals(s, PedersenBytesHash.hashToScalar(payload), name + " s");
            assertEquals(s, PedersenBytesHash.hashToScalar(
                    new PedersenBytesStreamTest.ChunkedStream(payload, 777), payload.length, true), name + " declared stream");
            assertEquals(s, PedersenBytesHash.hashToScalar(
                    new ByteArrayInputStream(payload), payload.length + 1L, false), name + " to-end stream");
        }
    }

    @Test
    @DisplayName("Commitments under the fixed test blindings match coordinates and encodings")
    void commitmentFixtures() {
        BigInteger r1 = scalar("r1");
        BigInteger r2 = scalar("r2");
        assertEquals(JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE), r1);
        int checked = 0;
        for (String name : payloadNames()) {
            for (String tag : new String[]{"r0", "r1", "r2"}) {
                String prefix = name + "_c_" + tag;
                if (!ref.containsKey(prefix + "_encode")) continue;
                BigInteger r = switch (tag) {
                    case "r0" -> BigInteger.ZERO;
                    case "r1" -> r1;
                    default -> r2;
                };
                byte[] payload = payload(name);
                PedersenBytesCommitment c = PedersenCommitment.commitBytes(payload, r);
                assertEquals(ref.get(prefix + "_encode"), HEX.formatHex(c.toPointBytes()), prefix);
                JubjubPoint point = c.point();
                assertEquals(scalar(prefix + "_u"), point.affineU(), prefix + " u");
                assertEquals(scalar(prefix + "_v"), point.affineV(), prefix + " v");
                assertTrue(PedersenCommitment.verifyBytes(
                        PedersenBytesCommitment.decode(HEX.parseHex(ref.get(prefix + "_encode"))), payload, r));
                checked++;
            }
        }
        assertTrue(checked >= 11, "commitment fixtures checked: " + checked);
    }

    @Test
    @DisplayName("Every algorithm mutation gives a different s; the library gives the true s")
    void mutationsAreDistinguished() {
        byte[] payload = payload(ref.get("mut_payload"));
        BigInteger mine = PedersenBytesHash.hashToScalar(payload);
        assertEquals(scalar("mut_true_s"), mine);
        int mutants = 0;
        for (Map.Entry<String, String> e : ref.entrySet()) {
            String key = e.getKey();
            if (!key.startsWith("mut_") || !key.endsWith("_s") || key.equals("mut_true_s")) continue;
            if (key.startsWith("mut_signed")) continue; // see below
            assertNotEquals(new BigInteger(e.getValue().substring(2), 16), mine, key + " must be distinguished");
            mutants++;
        }
        assertTrue(mutants >= 13, "mutation fixtures: " + mutants);

        // The signed-interpretation mutant coincides on the main payload (its uniform bytes have the
        // top bit clear), so the reference demonstrates it on a payload whose bytes do not.
        assertEquals("false", ref.get("mut_signed_utf8_text_u_top_bit_set"));
        byte[] alt = payload(ref.get("mut_signed_alt_payload"));
        assertEquals(scalar("mut_signed_alt_true_s"), PedersenBytesHash.hashToScalar(alt));
        assertNotEquals(scalar("mut_signed_alt_s"), PedersenBytesHash.hashToScalar(alt));
    }

    @Test
    @DisplayName("Rejected point encodings are rejected by the byte decoder; the identity is accepted")
    void decodingFixtures() {
        List<String> rejected = new ArrayList<>();
        for (Map.Entry<String, String> e : ref.entrySet()) {
            if (!e.getKey().startsWith("neg_") || !e.getKey().endsWith("_input")) continue;
            String base = e.getKey().substring(0, e.getKey().length() - "_input".length());
            assertEquals("reject", ref.get(base + "_expected"), base);
            byte[] input = HEX.parseHex(e.getValue());
            assertThrows(IllegalArgumentException.class, () -> PedersenBytesCommitment.decode(input), base);
            rejected.add(base);
        }
        assertTrue(rejected.size() >= 8, "negative decoding fixtures: " + rejected);

        assertEquals("accept", ref.get("pos_identity_expected"));
        PedersenBytesCommitment identity = PedersenBytesCommitment.decode(HEX.parseHex(ref.get("pos_identity_input")));
        assertTrue(identity.point().isIdentity());
        assertFalse(PedersenCommitment.verifyBytes(identity, new byte[0], BigInteger.ZERO));
    }

    private static List<String> payloadNames() {
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, String> e : ref.entrySet()) {
            String key = e.getKey();
            if (!key.startsWith("check_") && key.endsWith("_n") && e.getValue().matches("[0-9]+")
                    && ref.containsKey(key.substring(0, key.length() - 2) + "_s")) {
                names.add(key.substring(0, key.length() - 2));
            }
        }
        return names;
    }

    /** Rebuilds a fixture payload from its pinned hex or from the recipe the reference states. */
    private static byte[] payload(String name) {
        String hex = ref.get(name + "_payload");
        if (hex != null) {
            return HEX.parseHex(hex);
        }
        int n = Integer.parseInt(ref.get(name + "_n"));
        String recipe = ref.get(name + "_recipe");
        if (name.equals("all_bytes")) {
            assertEquals("payload[i] = i for i = 0..255 (256 octets)", recipe);
            byte[] b = new byte[n];
            for (int i = 0; i < n; i++) b[i] = (byte) i;
            return b;
        }
        if (name.startsWith("pattern_")) {
            assertTrue(recipe.startsWith("payload[i] = (131*i + 17) mod 256"), recipe);
            return PedersenBytesStreamTest.pattern(n);
        }
        throw new AssertionError("no payload or known recipe for " + name + ": " + recipe);
    }

    private static BigInteger scalar(String key) {
        String v = Objects.requireNonNull(ref.get(key), key);
        return new BigInteger(v.substring(2), 16);
    }
}
