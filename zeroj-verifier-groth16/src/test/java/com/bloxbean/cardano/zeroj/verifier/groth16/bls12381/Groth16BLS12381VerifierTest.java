package com.bloxbean.cardano.zeroj.verifier.groth16.bls12381;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Groth16BLS12381VerifierTest {

    private final Groth16BLS12381Verifier verifier = new Groth16BLS12381Verifier();

    @Test
    void verifyValidBLS12381Proof() {
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bls12381/proof.json",
                "/test-vectors/groth16-bls12381/public.json",
                "multiplier-bls");
        var material = loadMaterial(
                "/test-vectors/groth16-bls12381/verification_key.json",
                "multiplier-bls");

        var result = verifier.verify(envelope, material);
        assertTrue(result.proofValid(), "Real BLS12-381 proof should be valid. Got: " + result);
    }

    @Test
    void descriptorIsBLS12381Groth16() {
        var desc = verifier.descriptor();
        assertEquals(ProofSystemId.GROTH16, desc.proofSystem());
        assertEquals(CurveId.BLS12_381, desc.curve());
        assertTrue(desc.supports(ProofSystemId.GROTH16, CurveId.BLS12_381));
        assertFalse(desc.supports(ProofSystemId.GROTH16, CurveId.BN254));
    }

    // --- Helpers ---

    private ZkProofEnvelope loadEnvelope(String proofPath, String publicPath, String circuitName) {
        String proofJson = loadString(proofPath);
        String publicJson = loadString(publicPath);
        String vkPath = proofPath.replace("proof.json", "verification_key.json");
        String vkJson = loadString(vkPath);
        return SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, new CircuitId(circuitName));
    }

    private VerificationMaterial loadMaterial(String vkPath, String circuitName) {
        byte[] vkBytes = loadBytes(vkPath);
        return VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId(circuitName));
    }

    private InputStream load(String path) {
        var in = getClass().getResourceAsStream(path);
        if (in == null) fail("Resource not found: " + path);
        return in;
    }

    private byte[] loadBytes(String path) {
        try (var in = load(path)) { return in.readAllBytes(); }
        catch (Exception e) { return fail("Failed to read: " + path); }
    }

    private String loadString(String path) {
        try (var in = load(path)) { return new String(in.readAllBytes(), StandardCharsets.UTF_8); }
        catch (Exception e) { return fail("Failed to read: " + path); }
    }
}
