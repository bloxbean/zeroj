package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.PublicInputs;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class SnarkjsJsonCodecTest {

    private static final String PROOF_PATH = "/test-vectors/groth16-bn254/proof.json";
    private static final String VK_PATH = "/test-vectors/groth16-bn254/verification_key.json";
    private static final String PUBLIC_PATH = "/test-vectors/groth16-bn254/public.json";

    // --- Proof parsing ---

    @Test
    void parseRealSnarkjsProof() {
        var proof = SnarkjsJsonCodec.parseProof(loadResource(PROOF_PATH));
        assertEquals("groth16", proof.protocol());
        assertEquals("bn128", proof.curve());
        assertEquals(3, proof.piA().size());
        assertEquals(3, proof.piB().size());
        assertEquals(3, proof.piC().size());
        // z-coordinate should be 1 (affine)
        assertEquals(BigInteger.ONE, proof.piA().get(2));
        // G2 z-coordinate: [1, 0]
        assertEquals(BigInteger.ONE, proof.piB().get(2).get(0));
        assertEquals(BigInteger.ZERO, proof.piB().get(2).get(1));
    }

    @Test
    void parseProofString() {
        String json = """
                {
                  "pi_a": ["100", "200", "1"],
                  "pi_b": [["10", "20"], ["30", "40"], ["1", "0"]],
                  "pi_c": ["300", "400", "1"],
                  "protocol": "groth16",
                  "curve": "bn128"
                }
                """;
        var proof = SnarkjsJsonCodec.parseProof(json);
        assertEquals(BigInteger.valueOf(100), proof.piA().get(0));
        assertEquals(BigInteger.valueOf(200), proof.piA().get(1));
    }

    @Test
    void parseMissingPiAThrows() {
        InputStream in = loadResource("/test-vectors/malformed/proof-missing-pi_a.json");
        assertThrows(CodecException.class, () -> SnarkjsJsonCodec.parseProof(in));
    }

    @Test
    void parseEmptyJsonThrows() {
        InputStream in = loadResource("/test-vectors/malformed/empty.json");
        assertThrows(CodecException.class, () -> SnarkjsJsonCodec.parseProof(in));
    }

    // --- Verification key parsing ---

    @Test
    void parseRealVerificationKey() {
        var vk = SnarkjsJsonCodec.parseVerificationKey(loadResource(VK_PATH));
        assertEquals("groth16", vk.protocol());
        assertEquals("bn128", vk.curve());
        assertEquals(2, vk.nPublic());
        // IC should have nPublic + 1 = 3 entries
        assertEquals(3, vk.ic().size());
        // Each IC entry is a G1 point with 3 coordinates
        assertEquals(3, vk.ic().get(0).size());
        // vk_alpha_1 is a G1 point
        assertEquals(3, vk.vkAlpha1().size());
        // vk_beta_2 is a G2 point
        assertEquals(3, vk.vkBeta2().size());
        assertEquals(2, vk.vkBeta2().get(0).size());
    }

    @Test
    void parseVerificationKeyMissingFieldThrows() {
        assertThrows(CodecException.class, () ->
                SnarkjsJsonCodec.parseVerificationKey("{\"protocol\":\"groth16\"}"));
    }

    // --- Public inputs parsing ---

    @Test
    void parseRealPublicInputs() {
        PublicInputs inputs = SnarkjsJsonCodec.parsePublicInputs(loadResource(PUBLIC_PATH));
        assertEquals(2, inputs.size());
        assertEquals(BigInteger.valueOf(33), inputs.get(0)); // output: c = 3 * 11 = 33
        assertEquals(BigInteger.valueOf(3), inputs.get(1));   // public input: a = 3
    }

    @Test
    void parsePublicInputsString() {
        PublicInputs inputs = SnarkjsJsonCodec.parsePublicInputs("[\"42\", \"7\"]");
        assertEquals(2, inputs.size());
        assertEquals(BigInteger.valueOf(42), inputs.get(0));
        assertEquals(BigInteger.valueOf(7), inputs.get(1));
    }

    @Test
    void parsePublicInputsNotArrayThrows() {
        assertThrows(CodecException.class, () ->
                SnarkjsJsonCodec.parsePublicInputs("{\"a\": 1}"));
    }

    // --- Envelope construction ---

    @Test
    void toEnvelopeFromRealVectors() {
        var proof = SnarkjsJsonCodec.parseProof(loadResource(PROOF_PATH));
        var vk = SnarkjsJsonCodec.parseVerificationKey(loadResource(VK_PATH));
        var inputs = SnarkjsJsonCodec.parsePublicInputs(loadResource(PUBLIC_PATH));

        var envelope = SnarkjsJsonCodec.toEnvelope(proof, vk, inputs, new CircuitId("multiplier"));

        assertEquals(ProofSystemId.GROTH16, envelope.proofSystem());
        assertEquals(CurveId.BN254, envelope.curve());
        assertEquals("multiplier", envelope.circuitId().value());
        assertEquals(2, envelope.publicInputs().size());
        assertTrue(envelope.proofBytes().length > 0);
        assertEquals("snarkjs-json", envelope.proofFormat().orElse(null));
    }

    // --- Wrong protocol detection ---

    @Test
    void parseProofWithWrongProtocolReturnsPlonk() {
        var proof = SnarkjsJsonCodec.parseProof(
                loadResource("/test-vectors/malformed/proof-wrong-protocol.json"));
        assertEquals("plonk", proof.protocol());
        // This parses fine — the protocol check is done at the verifier level
    }

    // --- Helpers ---

    private InputStream loadResource(String path) {
        InputStream in = getClass().getResourceAsStream(path);
        if (in == null) {
            fail("Test resource not found: " + path);
        }
        return in;
    }
}
