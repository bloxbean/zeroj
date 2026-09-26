package org.zeroj.verifier.groth16.bls12381;

import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.VerificationResult;
import org.zeroj.api.ZkProofEnvelope;
import org.zeroj.backend.spi.ZkVerifier;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.codec.SnarkjsVerificationKey;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * ADR-0045 V1/V3 (affirming ADR-0025): both off-chain BLS12-381 Groth16 verifiers reject a
 * verification key whose {@code IC[0]} or {@code IC[i > 0]} is the point at infinity, encoded in
 * the canonical projective JSON form {@code ["0", "1", "0"]}, with the same reason code and
 * message. The JSON codec is transport: it parses the encoding and the verifier rejects it. The
 * unmodified shared vector verifies on both providers (the control).
 */
class Groth16BLS12381InfinityIcProfileTest {

    private static final String DIR = "/test-vectors/groth16-bls12381/";
    private static final List<BigInteger> PROJECTIVE_INFINITY = List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO);

    private final ZkVerifier pureJava = new Groth16BLS12381PureJavaVerifier();
    private final ZkVerifier blst = new Groth16BLS12381Verifier();

    @Test
    void control_sharedVectorVerifiesOnBothProviders() {
        String vkJson = load("verification_key.json");
        var envelope = envelope(vkJson);
        assertTrue(pureJava.verify(envelope, material(vkJson)).proofValid());
        assertTrue(blst.verify(envelope, material(vkJson)).proofValid());
    }

    @Test
    void infinityIcEntry_isRejectedIdenticallyByBothProviders() {
        var vk = SnarkjsJsonCodec.parseVerificationKey(load("verification_key.json"));
        for (int i = 0; i < vk.ic().size(); i++) {
            String tampered = vkJson(vk, Map.of(i, PROJECTIVE_INFINITY));
            // the codec still parses the canonical infinity encoding: enforcement is the verifier's
            assertEquals(PROJECTIVE_INFINITY, SnarkjsJsonCodec.parseVerificationKey(tampered).ic().get(i));
            var envelope = envelope(tampered);
            var pj = pureJava.verify(envelope, material(tampered));
            var bl = blst.verify(envelope, material(tampered));
            assertFalse(pj.proofValid(), "pure Java must reject IC[" + i + "] = infinity");
            assertFalse(bl.proofValid(), "blst must reject IC[" + i + "] = infinity");
            assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, pj.reasonCode().orElseThrow());
            assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, bl.reasonCode().orElseThrow());
            assertTrue(pj.message().orElseThrow().contains("vk.IC[" + i + "] must not be point at infinity"),
                    pj.message().orElseThrow());
            assertEquals(pj.message(), bl.message(), "providers must agree on IC[" + i + "]");
        }
    }

    @Test
    void infinityVkPoint_isRejectedIdenticallyByBothProviders() {
        var vk = SnarkjsJsonCodec.parseVerificationKey(load("verification_key.json"));
        var g2Infinity = List.of(List.of(BigInteger.ZERO, BigInteger.ZERO), List.of(BigInteger.ONE, BigInteger.ZERO),
                List.of(BigInteger.ZERO, BigInteger.ZERO));
        record Case(String label, SnarkjsVerificationKey vk) {}
        var cases = List.of(
                new Case("vk.alpha", new SnarkjsVerificationKey(vk.protocol(), vk.curve(), vk.nPublic(), PROJECTIVE_INFINITY,
                        vk.vkBeta2(), vk.vkGamma2(), vk.vkDelta2(), vk.vkAlphabeta12(), vk.ic())),
                new Case("vk.beta", new SnarkjsVerificationKey(vk.protocol(), vk.curve(), vk.nPublic(), vk.vkAlpha1(),
                        g2Infinity, vk.vkGamma2(), vk.vkDelta2(), vk.vkAlphabeta12(), vk.ic())),
                new Case("vk.gamma", new SnarkjsVerificationKey(vk.protocol(), vk.curve(), vk.nPublic(), vk.vkAlpha1(),
                        vk.vkBeta2(), g2Infinity, vk.vkDelta2(), vk.vkAlphabeta12(), vk.ic())),
                new Case("vk.delta", new SnarkjsVerificationKey(vk.protocol(), vk.curve(), vk.nPublic(), vk.vkAlpha1(),
                        vk.vkBeta2(), vk.vkGamma2(), g2Infinity, vk.vkAlphabeta12(), vk.ic())));
        for (var c : cases) {
            String tampered = vkJson(c.vk(), Map.of());
            var envelope = envelope(tampered);
            var pj = pureJava.verify(envelope, material(tampered));
            var bl = blst.verify(envelope, material(tampered));
            assertFalse(pj.proofValid(), c.label());
            assertFalse(bl.proofValid(), c.label());
            assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, pj.reasonCode().orElseThrow(), c.label());
            assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, bl.reasonCode().orElseThrow(), c.label());
            assertTrue(pj.message().orElseThrow().contains("must not be point at infinity"), pj.message().orElseThrow());
            assertEquals(pj.message(), bl.message(), c.label());
        }
    }

    // ---- helpers ----

    private ZkProofEnvelope envelope(String vkJson) {
        return SnarkjsJsonCodec.toEnvelopeFromJson(load("proof.json"), vkJson, load("public.json"),
                new CircuitId("multiplier-bls"));
    }

    private static VerificationMaterial material(String vkJson) {
        return VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8), ProofSystemId.GROTH16,
                CurveId.BLS12_381, new CircuitId("multiplier-bls"));
    }

    private String load(String name) {
        try (var in = getClass().getResourceAsStream(DIR + name)) {
            if (in == null) return fail("missing test vector " + DIR + name);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return fail("Failed to read " + name + ": " + e);
        }
    }

    /** Re-serializes a parsed VK in snarkjs JSON form, overriding chosen IC entries. */
    static String vkJson(SnarkjsVerificationKey vk, Map<Integer, List<BigInteger>> icOverride) {
        var sb = new StringBuilder("{\"protocol\":\"").append(vk.protocol()).append("\",\"curve\":\"").append(vk.curve())
                .append("\",\"nPublic\":").append(vk.nPublic());
        sb.append(",\"vk_alpha_1\":").append(q(vk.vkAlpha1()));
        sb.append(",\"vk_beta_2\":").append(q2(vk.vkBeta2()));
        sb.append(",\"vk_gamma_2\":").append(q2(vk.vkGamma2()));
        sb.append(",\"vk_delta_2\":").append(q2(vk.vkDelta2()));
        sb.append(",\"vk_alphabeta_12\":[");
        for (int i = 0; i < vk.vkAlphabeta12().size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(q2(vk.vkAlphabeta12().get(i)));
        }
        sb.append("],\"IC\":[");
        for (int i = 0; i < vk.ic().size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(q(icOverride.getOrDefault(i, vk.ic().get(i))));
        }
        return sb.append("]}").toString();
    }

    private static String q(List<BigInteger> v) {
        var sb = new StringBuilder("[");
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(v.get(i)).append('"');
        }
        return sb.append(']').toString();
    }

    private static String q2(List<List<BigInteger>> v) {
        var sb = new StringBuilder("[");
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append(q(v.get(i)));
        }
        return sb.append(']').toString();
    }
}
