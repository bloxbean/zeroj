package org.zeroj.bls12381;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 D9: the complete RFC 9380 vector sets for the BLS12-381 suites and the expanders,
 * loaded from {@code src/test/resources/rfc9380/}. Those files are machine-extracted from the RFC
 * text (see the README there), so no expected value is derived from the code under test.
 *
 * <p>For the RO suites the intermediate values are checked too: {@code u = hash_to_field(msg, 2)},
 * {@code Q0 = map_to_curve(u[0])}, {@code Q1 = map_to_curve(u[1])} and
 * {@code P = clear_cofactor(Q0 + Q1)}. For the NU suites: {@code u[0]}, {@code Q} and
 * {@code P = clear_cofactor(Q)}.</p>
 */
class Rfc9380VectorFileTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    // ---- J.9.1 / J.9.2: G1 ----

    @ParameterizedTest(name = "J.9.1 msg[{index}]")
    @MethodSource("j91")
    void g1RandomOracleSuite(JsonNode v, byte[] dst) {
        byte[] msg = ascii(v.get("msg").asText());
        BigInteger[] u = Bls12381Hash.hashToFp(msg, dst, 2);
        assertEquals(hex(v, "u[0]"), u[0]);
        assertEquals(hex(v, "u[1]"), u[1]);

        G1Point q0 = Bls12381HashToCurve.mapToCurveG1(Fp.of(u[0]));
        G1Point q1 = Bls12381HashToCurve.mapToCurveG1(Fp.of(u[1]));
        assertG1(v, "Q0", q0);
        assertG1(v, "Q1", q1);
        assertG1(v, "P", Bls12381HashToCurve.clearG1(q0.add(q1)));
        assertG1(v, "P", Bls12381Hash.hashToG1(msg, dst));
    }

    @ParameterizedTest(name = "J.9.2 msg[{index}]")
    @MethodSource("j92")
    void g1NonUniformSuite(JsonNode v, byte[] dst) {
        byte[] msg = ascii(v.get("msg").asText());
        BigInteger[] u = Bls12381Hash.hashToFp(msg, dst, 1);
        assertEquals(1, u.length);
        assertEquals(hex(v, "u[0]"), u[0]);

        G1Point q = Bls12381HashToCurve.mapToCurveG1(Fp.of(u[0]));
        assertG1(v, "Q", q);
        assertG1(v, "P", Bls12381HashToCurve.clearG1(q));
        assertG1(v, "P", Bls12381Hash.encodeToG1(msg, dst));
    }

    // ---- J.10.1 / J.10.2: G2 ----

    @ParameterizedTest(name = "J.10.1 msg[{index}]")
    @MethodSource("j101")
    void g2RandomOracleSuite(JsonNode v, byte[] dst) {
        byte[] msg = ascii(v.get("msg").asText());
        BigInteger[][] u = Bls12381Hash.hashToFp2(msg, dst, 2);
        assertFp2(v, "u[0]", fp2(u[0]));
        assertFp2(v, "u[1]", fp2(u[1]));

        G2Point q0 = Bls12381HashToCurve.mapToCurveG2(fp2(u[0]));
        G2Point q1 = Bls12381HashToCurve.mapToCurveG2(fp2(u[1]));
        assertG2(v, "Q0", q0);
        assertG2(v, "Q1", q1);
        assertG2(v, "P", Bls12381HashToCurve.clearG2(q0.add(q1)));
        assertG2(v, "P", Bls12381Hash.hashToG2(msg, dst));
    }

    @ParameterizedTest(name = "J.10.2 msg[{index}]")
    @MethodSource("j102")
    void g2NonUniformSuite(JsonNode v, byte[] dst) {
        byte[] msg = ascii(v.get("msg").asText());
        BigInteger[][] u = Bls12381Hash.hashToFp2(msg, dst, 1);
        assertEquals(1, u.length);
        assertFp2(v, "u[0]", fp2(u[0]));

        G2Point q = Bls12381HashToCurve.mapToCurveG2(fp2(u[0]));
        assertG2(v, "Q", q);
        assertG2(v, "P", Bls12381HashToCurve.clearG2(q));
        assertG2(v, "P", Bls12381Hash.encodeToG2(msg, dst));
    }

    // ---- K.1 / K.2 / K.6: expanders ----

    @ParameterizedTest(name = "K.1 [{index}]")
    @MethodSource("k1")
    void expandMessageXmdSha256(JsonNode v, byte[] dst) {
        assertExpand(v, Bls12381Hash.expandMessageXmdSha256(ascii(v.get("msg").asText()), dst, lenInBytes(v)));
    }

    /** K.2: a 256-octet DST, which the expander must reduce first (RFC 9380 §5.3.3). */
    @ParameterizedTest(name = "K.2 [{index}]")
    @MethodSource("k2")
    void expandMessageXmdSha256LongDst(JsonNode v, byte[] dst) {
        assertTrue(dst.length > 255, "K.2 must exercise the oversize-DST reduction");
        assertExpand(v, Bls12381Hash.expandMessageXmdSha256(ascii(v.get("msg").asText()), dst, lenInBytes(v)));
    }

    @ParameterizedTest(name = "K.6 [{index}]")
    @MethodSource("k6")
    void expandMessageXofShake256(JsonNode v, byte[] dst) {
        assertExpand(v, Bls12381Hash.expandMessageXofShake256(ascii(v.get("msg").asText()), dst, lenInBytes(v)));
    }

    @Test
    void everyVectorFileHasTheFullRfcSet() {
        assertEquals(5, vectors("j9_1_bls12381g1_xmd_sha256_sswu_ro.json").size());
        assertEquals(5, vectors("j9_2_bls12381g1_xmd_sha256_sswu_nu.json").size());
        assertEquals(5, vectors("j10_1_bls12381g2_xmd_sha256_sswu_ro.json").size());
        assertEquals(5, vectors("j10_2_bls12381g2_xmd_sha256_sswu_nu.json").size());
        assertEquals(10, vectors("k1_expand_message_xmd_sha256.json").size());
        assertEquals(10, vectors("k2_expand_message_xmd_sha256_long_dst.json").size());
        assertEquals(10, vectors("k6_expand_message_xof_shake256.json").size());
    }

    // ---- RFC 9380 §5.3.1 / §5.3.2 length bounds (negative tests) ----

    @Test
    void expandMessageXmd_lengthBound() {
        byte[] dst = ascii("QUUX-V01-CS02-with-expander-SHA256-128");
        // ell = ceil(len / 32) must be <= 255, so 255 * 32 = 8160 is the largest valid length.
        assertEquals(8160, Bls12381Hash.expandMessageXmdSha256(new byte[0], dst, 8160).length);
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Hash.expandMessageXmdSha256(new byte[0], dst, 8161));
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Hash.expandMessageXmdSha256(new byte[0], dst, -1));
    }

    @Test
    void expandMessageXof_lengthBound() {
        byte[] dst = ascii("QUUX-V01-CS02-with-expander-SHAKE256");
        // len_in_bytes is encoded as I2OSP(len, 2), so 65535 is the largest valid length.
        assertEquals(65535, Bls12381Hash.expandMessageXofShake256(new byte[0], dst, 65535).length);
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Hash.expandMessageXofShake256(new byte[0], dst, 65536));
        assertThrows(IllegalArgumentException.class,
                () -> Bls12381Hash.expandMessageXofShake256(new byte[0], dst, -1));
    }

    // ---- sources ----

    static Stream<Arguments> j91() { return suite("j9_1_bls12381g1_xmd_sha256_sswu_ro.json", "dst"); }
    static Stream<Arguments> j92() { return suite("j9_2_bls12381g1_xmd_sha256_sswu_nu.json", "dst"); }
    static Stream<Arguments> j101() { return suite("j10_1_bls12381g2_xmd_sha256_sswu_ro.json", "dst"); }
    static Stream<Arguments> j102() { return suite("j10_2_bls12381g2_xmd_sha256_sswu_nu.json", "dst"); }
    static Stream<Arguments> k1() { return suite("k1_expand_message_xmd_sha256.json", "DST"); }
    static Stream<Arguments> k2() { return suite("k2_expand_message_xmd_sha256_long_dst.json", "DST"); }
    static Stream<Arguments> k6() { return suite("k6_expand_message_xof_shake256.json", "DST"); }

    private static Stream<Arguments> suite(String file, String dstKey) {
        JsonNode doc = load(file);
        byte[] dst = ascii(doc.get("header").get(dstKey).asText());
        List<Arguments> out = new ArrayList<>();
        doc.get("vectors").forEach(v -> out.add(Arguments.of(v, dst)));
        return out.stream();
    }

    private static List<JsonNode> vectors(String file) {
        List<JsonNode> out = new ArrayList<>();
        load(file).get("vectors").forEach(out::add);
        return out;
    }

    private static JsonNode load(String file) {
        try (InputStream in = Rfc9380VectorFileTest.class.getResourceAsStream("/rfc9380/" + file)) {
            assertNotNull(in, "missing resource rfc9380/" + file);
            return JSON.readTree(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ---- helpers ----

    private static void assertExpand(JsonNode v, byte[] actual) {
        assertArrayEquals(HexFormat.of().parseHex(v.get("uniform_bytes").asText()), actual);
    }

    private static int lenInBytes(JsonNode v) {
        return Integer.decode(v.get("len_in_bytes").asText());
    }

    private static void assertG1(JsonNode v, String name, G1Point point) {
        assertEquals(Fp.of(hex(v, name + ".x")), point.x(), name + ".x");
        assertEquals(Fp.of(hex(v, name + ".y")), point.y(), name + ".y");
    }

    private static void assertG2(JsonNode v, String name, G2Point point) {
        assertFp2(v, name + ".x", point.x());
        assertFp2(v, name + ".y", point.y());
    }

    private static void assertFp2(JsonNode v, String key, Fp2 actual) {
        JsonNode pair = v.get(key);
        assertTrue(pair.isArray() && pair.size() == 2, key + " must be an Fp2 pair");
        assertEquals(Fp2.of(Fp.of(new BigInteger(pair.get(0).asText(), 16)),
                Fp.of(new BigInteger(pair.get(1).asText(), 16))), actual, key);
    }

    private static Fp2 fp2(BigInteger[] c) {
        return Fp2.of(Fp.of(c[0]), Fp.of(c[1]));
    }

    private static BigInteger hex(JsonNode v, String key) {
        return new BigInteger(v.get(key).asText(), 16);
    }

    private static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }
}
