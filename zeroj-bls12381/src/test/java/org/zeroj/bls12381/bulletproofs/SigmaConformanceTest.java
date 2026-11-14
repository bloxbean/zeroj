package org.zeroj.bls12381.bulletproofs;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.ec.G1Point;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0061 I12: {@code draft-irtf-cfrg-sigma-protocols-03} Appendix A.3 ({@code sigma-proofs_Shake128_BLS12381})
 * through the test-only {@link SigmaHarness}: the four gated A.3.1 proofs reproduce their session
 * identifiers and challenges and verify; all 32 A.3.2 vectors give their expected verdict at the
 * expected layer; the seven codec-layer rejections also fail directly in this package's decoders.
 */
class SigmaConformanceTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Set<String> GATED = Set.of("discrete_logarithm", "pedersen_commitment");
    private static final Set<String> CONTROLS = Set.of("batchable/F1", "compact/F1", "batchable/F2", "compact/F2");

    @Test
    @DisplayName("A.3.1 gate: discrete_logarithm and pedersen_commitment (batchable, compact) reproduce the session id and challenge and verify")
    void gatedValidProofs() {
        int gated = 0;
        for (JsonNode v : CfrgVectors.load(CfrgVectors.SIGMA)) {
            if (!GATED.contains(v.get("Relation").asText())) continue;
            checkValid(v);
            gated++;
        }
        assertEquals(4, gated);
    }

    @Test
    @DisplayName("A.3.1, outside the gate: the other ten valid proofs also verify (reported separately, spec §10)")
    void otherValidProofs() {
        int others = 0;
        for (JsonNode v : CfrgVectors.load(CfrgVectors.SIGMA)) {
            if (GATED.contains(v.get("Relation").asText())) continue;
            checkValid(v);
            others++;
        }
        assertEquals(10, others);
    }

    private static void checkValid(JsonNode v) {
        String id = v.get("Id").asText();
        assertEquals("accept", v.get("Expected").asText(), id);
        assertEquals("sigma-proofs_Shake128_BLS12381", v.get("Ciphersuite").asText(), id);
        String tag = v.get("Tag").asText();
        String flavor = v.get("Flavor").asText();
        assertTrue(tag.contains(flavor.equals("batchable") ? "-DSFS-" : "-CMPT-"), id);
        assertEquals(v.get("SessionId").asText(),
                HEX.formatHex(DuplexSponge.deriveSessionId(tag.getBytes(StandardCharsets.US_ASCII))), id);
        byte[] instanceBytes = HEX.parseHex(v.get("Instance").asText());
        byte[] narg = HEX.parseHex(v.get("NargString").asText());
        SigmaHarness.Result r = SigmaHarness.verify(flavor, tag, instanceBytes, narg);
        assertEquals(SigmaHarness.Layer.ACCEPT, r.layer(), id);
        if (flavor.equals("compact")) {
            // The compact NARG string carries the challenge: the transcript reproduced it exactly.
            assertEquals(new BigInteger(1, narg, 0, 32), r.challenge(), id);
        }
        // The published witness opens the instance: image == map(instance, witness).
        SigmaHarness.Instance inst = SigmaHarness.parse(instanceBytes);
        assertNotNull(inst, id);
        byte[] w = HEX.parseHex(v.get("Witness").asText());
        BigInteger[] witness = new BigInteger[w.length / 32];
        for (int i = 0; i < witness.length; i++) witness[i] = PointCodec.readScalar(w, 32 * i);
        assertEquals(SigmaHarness.image(inst), SigmaHarness.map(inst, witness), id);
    }

    @Test
    @DisplayName("A.3.2: 28 rejections and 4 acceptance controls, each at its layer")
    void adversarialVectors() {
        Map<String, SigmaHarness.Layer> expectedLayer = new LinkedHashMap<>();
        for (String s : List.of("batchable/A1", "batchable/A3", "batchable/A4", "batchable/A5", "batchable/A6",
                "batchable/B1", "compact/B2")) expectedLayer.put(s, SigmaHarness.Layer.DESERIALIZATION);
        for (String s : List.of("batchable/C1", "batchable/C2", "compact/C1", "compact/C2")) {
            expectedLayer.put(s, SigmaHarness.Layer.LENGTH);
        }
        for (String s : List.of("batchable/E1", "batchable/E1b", "batchable/E2", "batchable/E3", "batchable/E4")) {
            expectedLayer.put(s, SigmaHarness.Layer.INSTANCE);
        }
        for (String s : List.of("compact/D1", "batchable/F1b", "compact/F1b", "batchable/F2b", "compact/F2b",
                "batchable/F3", "compact/F3", "compact/F4", "batchable/F4b", "batchable/H1", "batchable/H2", "compact/H3")) {
            expectedLayer.put(s, SigmaHarness.Layer.VERIFICATION);
        }
        for (String s : CONTROLS) expectedLayer.put(s, SigmaHarness.Layer.ACCEPT);
        assertEquals(32, expectedLayer.size());

        int seen = 0;
        for (JsonNode v : CfrgVectors.load(CfrgVectors.SIGMA_INVALID)) {
            String id = v.get("Id").asText();
            String key = id.substring(id.lastIndexOf('/', id.lastIndexOf('/') - 1) + 1);
            SigmaHarness.Layer want = expectedLayer.get(key);
            assertNotNull(want, "unexpected vector " + id);
            assertEquals(CONTROLS.contains(key) ? "accept" : "reject", v.get("Expected").asText(), id);
            SigmaHarness.Result r = SigmaHarness.verify(v.get("Flavor").asText(), v.get("Tag").asText(),
                    HEX.parseHex(v.get("Instance").asText()), HEX.parseHex(v.get("NargString").asText()));
            assertEquals(want, r.layer(), id);
            if (want == SigmaHarness.Layer.DESERIALIZATION) {
                assertEquals(null, r.challenge(), id + ": failed before any challenge was derived");
            }
            seen++;
        }
        assertEquals(32, seen);
    }

    @Test
    @DisplayName("A.3.2 A1, A3–A6 and B1, B2 fail directly in this package's point and scalar decoders, with the spec §3 classes")
    void codecLayerRejectionsDirect() {
        Map<String, JsonNode> byKey = new LinkedHashMap<>();
        for (JsonNode v : CfrgVectors.load(CfrgVectors.SIGMA_INVALID)) {
            String id = v.get("Id").asText();
            byKey.put(id.substring(id.lastIndexOf('/', id.lastIndexOf('/') - 1) + 1), v);
        }
        byte[] validBatchable = HEX.parseHex(byKey.get("batchable/F1").get("NargString").asText());
        byte[] validCompact = HEX.parseHex(byKey.get("compact/F1").get("NargString").asText());
        Map<String, CommitmentError> points = Map.of("batchable/A1", CommitmentError.MALFORMED_ENCODING,
                "batchable/A3", CommitmentError.MALFORMED_ENCODING, "batchable/A4", CommitmentError.MALFORMED_ENCODING,
                "batchable/A5", CommitmentError.NOT_IN_SUBGROUP, "batchable/A6", CommitmentError.MALFORMED_ENCODING);
        for (Map.Entry<String, CommitmentError> e : points.entrySet()) {
            byte[] narg = HEX.parseHex(byKey.get(e.getKey()).get("NargString").asText());
            byte[] point = changedChunk(validBatchable, narg, 0, 48);
            CommitmentFormatException ex = assertThrows(CommitmentFormatException.class, () -> PointCodec.decode(point), e.getKey());
            assertEquals(e.getValue(), ex.reason(), e.getKey());
        }
        byte[] b1 = HEX.parseHex(byKey.get("batchable/B1").get("NargString").asText());
        byte[] response = changedChunk(validBatchable, b1, 48, 32);
        assertEquals(CommitmentError.NON_CANONICAL_SCALAR,
                assertThrows(CommitmentFormatException.class, () -> PointCodec.readScalar(response, 0)).reason());
        byte[] b2 = HEX.parseHex(byKey.get("compact/B2").get("NargString").asText());
        byte[] challenge = changedChunk(validCompact, b2, 0, 32);
        assertEquals(CommitmentError.NON_CANONICAL_SCALAR,
                assertThrows(CommitmentFormatException.class, () -> PointCodec.readScalar(challenge, 0)).reason());
        // The identity encoding is exactly what A4 carries.
        byte[] identity = new byte[48];
        identity[0] = (byte) 0xC0;
        byte[] a4 = changedChunk(validBatchable, HEX.parseHex(byKey.get("batchable/A4").get("NargString").asText()), 0, 48);
        assertTrue(Arrays.equals(identity, a4));
        assertTrue(G1Point.INFINITY.isInfinity());
    }

    @Test
    @DisplayName("Harness self-check: instance-validation check 10 (a column that sums to the identity) rejects, which no A.3.2 vector exercises")
    void harnessCheckTen() {
        // One equation X = x·G + x·(−G) with X = G: every element is used, the image is not the
        // identity, but the column of scalar 0 sums to the identity (sigma-03 §3.5 check 10).
        BigInteger one = BigInteger.ONE;
        BigInteger minusOne = PointCodec.Q.subtract(one);
        G1Point g = Bls12381Generators.G1;
        SigmaHarness.Instance inst = new SigmaHarness.Instance(List.of(g, g),
                List.of(new SigmaHarness.Equation(List.of(new SigmaHarness.ImageTerm(1, one)),
                        List.of(new SigmaHarness.Term(0, 0, one), new SigmaHarness.Term(0, 1, minusOne)))), new byte[0]);
        assertEquals(false, SigmaHarness.validate(inst));
        SigmaHarness.Instance fine = new SigmaHarness.Instance(List.of(g, g),
                List.of(new SigmaHarness.Equation(List.of(new SigmaHarness.ImageTerm(1, one)),
                        List.of(new SigmaHarness.Term(0, 0, one), new SigmaHarness.Term(0, 1, one)))), new byte[0]);
        assertEquals(true, SigmaHarness.validate(fine));
    }

    /** The {@code size}-octet chunk at {@code offset} of {@code mutated}, which must differ from {@code valid} only there. */
    private static byte[] changedChunk(byte[] valid, byte[] mutated, int offset, int size) {
        assertEquals(valid.length, mutated.length);
        for (int i = 0; i < valid.length; i++) {
            if (i < offset || i >= offset + size) assertEquals(valid[i], mutated[i], "octet " + i + " outside the chunk changed");
        }
        byte[] chunk = Arrays.copyOfRange(mutated, offset, offset + size);
        assertTrue(!Arrays.equals(chunk, Arrays.copyOfRange(valid, offset, offset + size)), "the chunk is unchanged");
        return chunk;
    }
}
