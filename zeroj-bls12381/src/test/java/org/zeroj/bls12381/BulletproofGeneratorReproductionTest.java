package org.zeroj.bls12381;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.ec.G1Point;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 M0: the Java reproduction of the {@code bulletproof-bls12-381-g1-gens-v1} generator set
 * ({@code docs/specs/bulletproof-range-bls12-381-g1-v1.md} §2). The expected digest is the value the
 * independent Python implementation ({@code src/test/resources/bulletproof-g1-reference/}) produced
 * without reading this code; this test recomputes every generator from RFC 9380 primitives.
 */
class BulletproofGeneratorReproductionTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final byte[] DST_BP =
            "ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.US_ASCII);
    private static final int VECTOR_LENGTH = 64;

    /** {@code D_gens}, spec §2.3 and Appendix A. */
    private static final String D_GENS = "69abb9e71b740d9be84f63bb146a63467ee452654340f1b09e8be6101e00ef19";

    /** The ADR-0060 bases, {@code pedersen-bls12-381-g1-v1.md} §2.2. */
    private static final String G =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String H =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";

    @Test
    @DisplayName("DST_BP is the pinned 70-octet ASCII tag")
    void tag() {
        assertEquals(70, DST_BP.length);
        assertEquals("ZeroJ-bulletproof-bls12-381-g1-gens-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_",
                new String(DST_BP, StandardCharsets.US_ASCII));
    }

    @Test
    @DisplayName("The 129 generators hash to D_gens and pass the §2.2 checks against each other and G, H")
    void generators() throws NoSuchAlgorithmException {
        List<G1Point> set = derive();
        assertEquals(2 * VECTOR_LENGTH + 1, set.size());

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        for (G1Point p : set) {
            sha256.update(Bls12381Codecs.g1ToCompressed(p));
        }
        assertEquals(D_GENS, HEX.formatHex(sha256.digest()));

        List<G1Point> all = new ArrayList<>(set);
        all.add(Bls12381Codecs.g1FromCompressed(HEX.parseHex(G)));
        all.add(Bls12381Codecs.g1FromCompressed(HEX.parseHex(H)));
        for (G1Point p : all) {
            assertFalse(p.isInfinity());
            assertTrue(p.isOnCurve());
            assertTrue(p.isInSubgroup());
        }
        for (int i = 0; i < all.size(); i++) {
            for (int j = i + 1; j < all.size(); j++) {
                assertNotEquals(all.get(i), all.get(j), "points " + i + " and " + j + " are equal");
                assertNotEquals(all.get(i), all.get(j).negate(), "points " + i + " and " + j + " are negatives");
            }
        }
    }

    @Test
    @DisplayName("Every encoding equals the independent Python implementation's generators-v1.json")
    void matchesPythonImplementation() throws IOException {
        JsonNode file;
        try (InputStream in = getClass().getResourceAsStream("/bulletproof-g1-reference/generators-v1.json")) {
            assertNotNull(in, "generators-v1.json missing from the test classpath");
            file = new ObjectMapper().readTree(in);
        }
        assertEquals("bulletproof-bls12-381-g1-gens-v1", file.get("generatorSetId").asText());
        assertEquals(new String(DST_BP, StandardCharsets.US_ASCII), file.get("DST").asText());
        assertEquals(D_GENS, file.get("D_gens").asText());
        assertEquals(G, file.get("pedersenG").asText());
        assertEquals(H, file.get("pedersenH").asText());

        List<G1Point> set = derive();
        JsonNode generators = file.get("generators");
        assertEquals(set.size(), generators.size());
        for (int i = 0; i < set.size(); i++) {
            String name = i < VECTOR_LENGTH ? "G_" + i : i < 2 * VECTOR_LENGTH ? "H_" + (i - VECTOR_LENGTH) : "U";
            assertEquals(name, generators.get(i).get("name").asText());
            assertEquals(generators.get(i).get("compressedHex").asText(),
                    HEX.formatHex(Bls12381Codecs.g1ToCompressed(set.get(i))), name);
        }
    }

    @Test
    @DisplayName("The index is a 4-octet big-endian suffix after the single-octet label")
    void messages() {
        assertEquals("4700000005", HEX.formatHex(message('G', 5)));
        assertEquals("480000003f", HEX.formatHex(message('H', 63)));
    }

    private static List<G1Point> derive() {
        List<G1Point> set = new ArrayList<>(2 * VECTOR_LENGTH + 1);
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            set.add(Bls12381Hash.hashToG1(message('G', i), DST_BP));
        }
        for (int i = 0; i < VECTOR_LENGTH; i++) {
            set.add(Bls12381Hash.hashToG1(message('H', i), DST_BP));
        }
        set.add(Bls12381Hash.hashToG1(new byte[] {'U'}, DST_BP));
        return set;
    }

    private static byte[] message(char label, int index) {
        return new byte[] {(byte) label, (byte) (index >>> 24), (byte) (index >>> 16), (byte) (index >>> 8), (byte) index};
    }
}
