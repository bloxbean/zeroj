package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0051 M3: the library against the independent {@code pedersen-jubjub-vector-v1} reference.
 *
 * <p>{@code src/test/resources/pedersen-vector-reference/reference-output.txt} was produced by a
 * standard-library Python implementation written from {@code docs/specs/pedersen-jubjub-vector-v1.md}
 * and {@code pedersen-jubjub-v1.md} only — no ZeroJ Java source was read — with its own Jubjub
 * arithmetic, {@code hashlib} BLAKE2s and SHA-256. Regenerate with
 * {@code python3 pedersen_jubjub_vector_v1_reference.py} in that directory.
 */
class PedersenVectorReferenceVectorsTest {

    private static final String RESOURCE = "/pedersen-vector-reference/reference-output.txt";
    private static Map<String, String> ref;

    private static final PedersenVectorSchema TWO = PedersenVectorSchema.of("zeroj.example.balance", 1,
            List.of(new PedersenVectorSchema.Entry("amount", 64), new PedersenVectorSchema.Entry("asset", 32)));

    @BeforeAll
    static void load() throws IOException {
        ref = new LinkedHashMap<>();
        try (InputStream in = Objects.requireNonNull(
                PedersenVectorReferenceVectorsTest.class.getResourceAsStream(RESOURCE), RESOURCE);
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
        assertEquals("pass", ref.get("result"));
        long checks = ref.entrySet().stream()
                .filter(e -> e.getKey().startsWith("spec_match_") || e.getKey().startsWith("check_"))
                .peek(e -> assertEquals("true", e.getValue(), e.getKey()))
                .count();
        assertTrue(checks > 100, "expected the full set of reference checks, got " + checks);
    }

    @Test
    @DisplayName("Pinned bases equal the reference bases")
    void bases() {
        for (int i = 0; i < PedersenVectorBases.MAX_DIMENSION; i++) {
            assertPoint("base_G_" + i, PedersenVectorBases.valueBase(i));
        }
        assertPoint("base_H_V", PedersenVectorBases.blindingBase());
    }

    @Test
    @DisplayName("Commitments match the reference, including padding, identity, 16 values and homomorphism")
    void commitments() {
        var one = PedersenVectorSchema.of("zeroj.example.one", 1, List.of(new PedersenVectorSchema.Entry("amount", 64)));
        assertCommit("commit_1000_7_r12345", TWO, List.of(1000L, 7L), BigInteger.valueOf(12345));
        assertCommit("commit_1000_r12345", one, List.of(1000L), BigInteger.valueOf(12345));
        assertCommit("commit_1000_0_r12345", TWO, List.of(1000L, 0L), BigInteger.valueOf(12345));
        assertCommit("commit_zero_n1_r0", one, List.of(0L), BigInteger.ZERO);
        assertCommit("commit_hom_a_3_4_r5", TWO, List.of(3L, 4L), BigInteger.valueOf(5));
        assertCommit("commit_hom_b_10_20_r30", TWO, List.of(10L, 20L), BigInteger.valueOf(30));
        assertCommit("commit_hom_13_24_r35", TWO, List.of(13L, 24L), BigInteger.valueOf(35));

        List<PedersenVectorSchema.Entry> entries = new ArrayList<>();
        List<Long> zeros = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            entries.add(new PedersenVectorSchema.Entry("v" + i, 64));
            zeros.add(0L);
        }
        var sixteen = PedersenVectorSchema.of("zeroj.example.sixteen", 1, entries);
        assertCommit("commit_zero_n16_r0", sixteen, zeros, BigInteger.ZERO);
        List<Long> seq = new ArrayList<>();
        for (String v : ref.get("commit_seq16_values").split(",")) seq.add(new BigInteger(v.substring(2), 16).longValueExact());
        assertCommit("commit_seq16", sixteen, seq, hex("commit_seq16_r"));
    }

    @Test
    @DisplayName("Schema encodings and digests match, including the boundary and leading-punctuation cases")
    void schemas() {
        for (String name : List.of("balance_v1", "balance_v2", "balance_v1_labels_swapped",
                "balance_v1_asset_width_33", "boundary_max", "literal_label_leading_punct")) {
            byte[] encoding = HexFormat.of().parseHex(ref.get("schema_" + name + "_encode"));
            PedersenVectorSchema schema = PedersenVectorSchema.decode(encoding);
            assertArrayEquals(encoding, schema.encode(), name);
            assertEquals(hex("schema_" + name + "_digest"), schema.digest(), name);
        }
        assertEquals(TWO, PedersenVectorSchema.decode(HexFormat.of().parseHex(ref.get("schema_balance_v1_encode"))));
    }

    @Test
    @DisplayName("Every negative schema encoding is rejected")
    void schemaNegatives() {
        List<String> names = ref.keySet().stream()
                .filter(k -> k.startsWith("schema_neg_") && k.endsWith("_input"))
                .toList();
        assertEquals(16, names.size(), "negative schema vector count");
        for (String key : names) {
            byte[] input = HexFormat.of().parseHex(ref.get(key));
            assertThrows(IllegalArgumentException.class, () -> PedersenVectorSchema.decode(input), key);
        }
    }

    @Test
    @DisplayName("Every negative point encoding is rejected by decode")
    void pointNegatives() {
        List<String> names = ref.keySet().stream()
                .filter(k -> k.startsWith("point_decode_neg_") && k.endsWith("_input"))
                .toList();
        assertTrue(names.size() >= 8, "negative point vector count");
        for (String key : names) {
            byte[] input = HexFormat.of().parseHex(ref.get(key));
            assertThrows(IllegalArgumentException.class, () -> PedersenVectorCommitment.decode(TWO, input), key);
        }
    }

    private static void assertCommit(String prefix, PedersenVectorSchema schema, List<Long> values, BigInteger r) {
        List<BigInteger> bigValues = values.stream().map(BigInteger::valueOf).toList();
        var c = PedersenVectorCommitment.commit(schema, bigValues, r);
        assertPoint(prefix, c.point());
        assertTrue(c.verify(bigValues, r), prefix);
    }

    private static void assertPoint(String prefix, JubjubPoint p) {
        assertEquals(hex(prefix + "_u"), p.affineU(), prefix + "_u");
        assertEquals(hex(prefix + "_v"), p.affineV(), prefix + "_v");
        assertArrayEquals(HexFormat.of().parseHex(ref.get(prefix + "_encode")), p.toBytes(), prefix + "_encode");
    }

    private static BigInteger hex(String key) {
        String value = Objects.requireNonNull(ref.get(key), key);
        return new BigInteger(value.substring(2), 16);
    }
}
