package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 I12: the {@code draft-irtf-cfrg-fiat-shamir-03} Appendix B vectors in the scope of spec
 * §10: the codec vectors B.1.1, B.1.2, B.1.4–B.1.8, B.1.10, B.1.11 and the SHAKE128 duplex-sponge
 * vectors B.2.1–B.2.11. Every in-scope vector must be present and pass; out-of-scope vectors are
 * named explicitly, so a new vector in the file cannot go unnoticed: B.1.3 and B.1.9 (extension
 * fields), and B.1.12, B.1.13, B.2.12 and B.2.13 (the Mersenne31 sumcheck example).
 */
class FiatShamirConformanceTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final Set<String> CODEC_IN_SCOPE = Set.of("serialize_varlen", "serialize_uint", "varlen_empty",
            "decode_uint_wraparound", "serialize_field_be", "deserialize_uint_reject_modulus",
            "deserialize_uint_reject_short", "deserialize_varlen_reject_truncated", "deserialize_varlen_reject_overflow");
    private static final Set<String> CODEC_OUT_OF_SCOPE = Set.of("deserialize_field",
            "deserialize_field_reject_second_coordinate", "sumcheck_reject_noncanonical_coefficient",
            "sumcheck_reject_round_identity");

    private static final Set<String> SHAKE_IN_SCOPE = Set.of("init_squeeze", "absorb_squeeze", "absorb_split", "stream",
            "empty_absorb", "interleave", "multiblock", "rate_block", "squeeze_zero", "derive_sid", "decode_uint");
    private static final Set<String> SHAKE_OUT_OF_SCOPE = Set.of("sumcheck", "sumcheck_reject_trailing_bytes");

    @Test
    @DisplayName("B.1 codec vectors in scope (9) pass; the rest are the named out-of-scope set")
    void codecVectors() {
        Map<String, JsonNode> byName = byName(CfrgVectors.load(CfrgVectors.CODEC));
        assertEquals(union(CODEC_IN_SCOPE, CODEC_OUT_OF_SCOPE), new TreeSet<>(byName.keySet()));
        for (String name : CODEC_IN_SCOPE) {
            JsonNode v = byName.get(name);
            String function = v.get("Function").asText();
            switch (function) {
                case "SerializeVarLenString" -> assertEquals(v.get("Output").asText(),
                        HEX.formatHex(FsCodec.serializeVarLenString(HEX.parseHex(v.get("Input").asText()))), name);
                case "SerializeUint" -> assertEquals(v.get("Output").asText(),
                        HEX.formatHex(FsCodec.serializeUint(hexInt(v.get("Value")), hexInt(v.get("Modulus")))), name);
                case "SerializeField" -> {
                    assertEquals("big-endian", v.get("ByteOrder").asText(), name);
                    assertEquals(v.get("Output").asText(),
                            HEX.formatHex(FsCodec.serializeFieldBigEndian(hexInt(v.get("Value")), hexInt(v.get("Modulus")))), name);
                }
                case "DecodeUint" -> assertEquals(hexInt(v.get("Challenge")),
                        FsCodec.decodeUint(HEX.parseHex(v.get("Input").asText()), hexInt(v.get("Modulus"))), name);
                case "DeserializeUint" -> {
                    assertEquals("reject", v.get("Expected").asText(), name);
                    assertNull(FsCodec.deserializeUint(HEX.parseHex(v.get("Input").asText()), hexInt(v.get("Modulus"))), name);
                }
                case "DeserializeVarLenString" -> {
                    assertEquals("reject", v.get("Expected").asText(), name);
                    assertNull(FsCodec.deserializeVarLenString(HEX.parseHex(v.get("Input").asText())), name);
                }
                default -> throw new AssertionError("unexpected in-scope function " + function);
            }
        }
        // The accepting counterparts of the two rejection families, which the draft does not list.
        assertEquals(BigInteger.valueOf(0xdeadbeefL), FsCodec.deserializeUint(
                HEX.parseHex("efbeadde00000000000000000000000000000000000000000000000000000000"),
                hexInt(byName.get("deserialize_uint_reject_modulus").get("Modulus"))));
        assertArrayEquals(HEX.parseHex("70726f6f66"), FsCodec.deserializeVarLenString(HEX.parseHex("0500000070726f6f66")));
    }

    @Test
    @DisplayName("B.2 SHAKE128 duplex-sponge vectors in scope (11) pass; the rest are the named out-of-scope set")
    void shake128Vectors() {
        Map<String, JsonNode> byName = byName(CfrgVectors.load(CfrgVectors.SHAKE128));
        assertEquals(union(SHAKE_IN_SCOPE, SHAKE_OUT_OF_SCOPE), new TreeSet<>(byName.keySet()));
        for (String name : SHAKE_IN_SCOPE) {
            JsonNode v = byName.get(name);
            assertEquals("SHAKE128", v.get("Hash").asText(), name);
            String function = v.get("Function").asText();
            switch (function) {
                case "DuplexSponge" -> assertEquals(v.get("Output").asText(), HEX.formatHex(replay(v)), name);
                case "DeriveSessionID" -> assertEquals(v.get("Output").asText(),
                        HEX.formatHex(DuplexSponge.deriveSessionId(HEX.parseHex(v.get("Tag").asText()))), name);
                case "DecodeUint" -> {
                    byte[] squeezed = replay(v);
                    assertEquals(v.get("Output").asText(), HEX.formatHex(squeezed), name);
                    assertEquals(hexInt(v.get("Challenge")), FsCodec.decodeUint(squeezed, hexInt(v.get("Modulus"))), name);
                }
                default -> throw new AssertionError("unexpected in-scope function " + function);
            }
        }
    }

    /** Runs a vector's operation list on a fresh sponge; returns the concatenated squeezes. */
    private static byte[] replay(JsonNode v) {
        DuplexSponge ds = DuplexSponge.init(HEX.parseHex(v.get("SessionId").asText()));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (JsonNode op : v.get("Operations")) {
            switch (op.get("type").asText()) {
                case "absorb" -> ds.absorb(HEX.parseHex(op.get("data").asText()));
                case "squeeze" -> out.writeBytes(ds.squeeze(op.get("length").asInt()));
                default -> throw new AssertionError("unknown operation " + op);
            }
        }
        return out.toByteArray();
    }

    private static Map<String, JsonNode> byName(JsonNode array) {
        Map<String, JsonNode> out = new LinkedHashMap<>();
        for (JsonNode v : array) {
            assertTrue(out.put(v.get("Name").asText(), v) == null, "duplicate " + v.get("Name"));
        }
        return out;
    }

    private static BigInteger hexInt(JsonNode node) {
        String s = node.asText();
        assertTrue(s.startsWith("0x"), s);
        return new BigInteger(s.substring(2), 16);
    }

    private static Set<String> union(Set<String> a, Set<String> b) {
        Set<String> out = new TreeSet<>(a);
        out.addAll(b);
        return out;
    }
}
