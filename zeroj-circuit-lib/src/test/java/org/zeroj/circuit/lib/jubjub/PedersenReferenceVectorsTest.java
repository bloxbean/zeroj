package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * ADR-0051 M0: the library against the independent {@code pedersen-jubjub-v1} reference.
 *
 * <p>{@code src/test/resources/pedersen-reference/reference-output.txt} was produced by a
 * standard-library Python implementation written from {@code docs/specs/pedersen-jubjub-v1.md}
 * and the ADR-0015 Sage Poseidon reference only — no ZeroJ Java source was read. Every value
 * below is therefore computed twice, by unrelated code, and compared here. Regenerate with
 * {@code python3 pedersen_jubjub_v1_reference.py} in that directory.
 */
class PedersenReferenceVectorsTest {

    private static final String RESOURCE = "/pedersen-reference/reference-output.txt";
    private static Map<String, String> ref;

    @BeforeAll
    static void load() throws IOException {
        ref = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(
                PedersenReferenceVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE);
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
    @DisplayName("The reference run passed its own self-checks and matched every spec pin")
    void referenceRunPassed() {
        assertEquals("pedersen-jubjub-v1", ref.get("profile"));
        assertEquals("pass", ref.get("result"));
        ref.forEach((key, value) -> {
            if (key.startsWith("spec_match_") || key.startsWith("selfcheck.")
                    || key.startsWith("check.") || key.startsWith("roundtrip.")) {
                assertEquals("true", value, key);
            }
        });
    }

    @Test
    @DisplayName("Curve constants match")
    void curveConstants() {
        assertEquals(JubjubCurve.BASE_FIELD_PRIME, hex("curve.p"));
        assertEquals(JubjubCurve.SUBGROUP_ORDER, hex("curve.l"));
        assertEquals(JubjubCurve.A, hex("curve.a"));
        assertEquals(JubjubCurve.D, hex("curve.d"));
    }

    @Test
    @DisplayName("Poseidon known answers match")
    void poseidonKnownAnswers() {
        var params = PoseidonParamsBLS12_381T3.INSTANCE;
        assertEquals(hex("poseidon2.0_0"), PoseidonHash.hash(params, BigInteger.ZERO, BigInteger.ZERO));
        assertEquals(hex("poseidon2.1_2"), PoseidonHash.hash(params, BigInteger.ONE, BigInteger.TWO));
        assertEquals(hex("poseidon2.123_456"),
                PoseidonHash.hash(params, BigInteger.valueOf(123), BigInteger.valueOf(456)));
    }

    @Test
    @DisplayName("Bases G and H match coordinates and encodings")
    void bases() {
        assertPoint("g", JubjubPoint.SUBGROUP_GENERATOR);
        assertPoint("h", PedersenCommitment.H);
    }

    @Test
    @DisplayName("Every reference commitment matches, through both commit and verify")
    void commitments() {
        List<String> cases = ref.keySet().stream()
                .filter(k -> k.startsWith("commit.") && k.endsWith(".value"))
                .map(k -> k.substring("commit.".length(), k.length() - ".value".length()))
                .toList();
        assertEquals(10, cases.size(), "reference case count");
        for (String c : cases) {
            BigInteger value = hex("commit." + c + ".value");
            BigInteger blinding = hex("commit." + c + ".blinding");
            JubjubPoint commitment = PedersenCommitment.commit(value, blinding);
            assertPoint("commit." + c, commitment);
            assertTrue(PedersenCommitment.verify(commitment, value, blinding), c);
            assertTrue(JubjubPoint.fromBytes(commitment.toBytes()).projectiveEquals(commitment), c);
        }
    }

    @Test
    @DisplayName("Homomorphic wrap example holds: C(l−1,17) + C(1,23) = C(0,40)")
    void wrapExample() {
        JubjubPoint sum = point("commit.c_lm1_17").add(point("commit.c_1_23"));
        assertTrue(sum.projectiveEquals(point("commit.c_0_40")));
    }

    @Test
    @DisplayName("Every negative decode vector is rejected the way the reference expects")
    void negativeDecodes() {
        List<String> names = ref.keySet().stream()
                .filter(k -> k.startsWith("decode_neg.") && k.endsWith(".expected"))
                .map(k -> k.substring("decode_neg.".length(), k.length() - ".expected".length()))
                .toList();
        assertEquals(12, names.size(), "negative vector count");
        for (String name : names) {
            byte[] input = HexFormat.of().parseHex(ref.get("decode_neg." + name + ".input"));
            String expected = ref.get("decode_neg." + name + ".expected");
            switch (expected) {
                case "reject_length", "reject_noncanonical_v", "reject_non_square",
                     "reject_u_zero_sign_set" ->
                        assertThrows(IllegalArgumentException.class,
                                () -> JubjubPoint.fromBytes(input), name);
                case "decodes_fails_subgroup" -> {
                    JubjubPoint decoded = JubjubPoint.fromBytes(input);
                    assertFalse(decoded.isInSubgroup(), name);
                    assertEquals(hex("decode_neg." + name + ".u"), decoded.affineU(), name);
                    assertEquals(hex("decode_neg." + name + ".v"), decoded.affineV(), name);
                }
                default -> fail("unknown expectation " + expected + " for " + name);
            }
        }
    }

    private static void assertPoint(String prefix, JubjubPoint p) {
        assertEquals(hex(prefix + ".u"), p.affineU(), prefix + ".u");
        assertEquals(hex(prefix + ".v"), p.affineV(), prefix + ".v");
        assertArrayEquals(HexFormat.of().parseHex(ref.get(prefix + ".encoding")), p.toBytes(),
                prefix + ".encoding");
    }

    private static JubjubPoint point(String prefix) {
        return JubjubPoint.fromAffine(hex(prefix + ".u"), hex(prefix + ".v"));
    }

    private static BigInteger hex(String key) {
        String value = Objects.requireNonNull(ref.get(key), key);
        if (!value.startsWith("0x")) throw new IllegalStateException(key + " is not hex: " + value);
        return new BigInteger(value.substring(2), 16);
    }
}
