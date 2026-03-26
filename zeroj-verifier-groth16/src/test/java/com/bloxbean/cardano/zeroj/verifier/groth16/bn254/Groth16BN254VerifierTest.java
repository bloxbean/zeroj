package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import org.junit.jupiter.api.Test;

import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.*;

class Groth16BN254VerifierTest {

    private final Groth16BN254Verifier verifier = new Groth16BN254Verifier();

    @Test
    void verifyValidMultiplierProof() {
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bn254/proof.json",
                "/test-vectors/groth16-bn254/public.json",
                "multiplier");
        var material = loadMaterial(
                "/test-vectors/groth16-bn254/verification_key.json",
                "multiplier");

        var result = verifier.verify(envelope, material);
        assertTrue(result.proofValid(), "Real snarkjs BN254 proof should be valid. Got: " + result);
    }

    @Test
    void verifyValidCubicProof() {
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bn254-cubic/proof.json",
                "/test-vectors/groth16-bn254-cubic/public.json",
                "cubic");
        var material = loadMaterial(
                "/test-vectors/groth16-bn254-cubic/verification_key.json",
                "cubic");

        var result = verifier.verify(envelope, material);
        assertTrue(result.proofValid(), "Cubic proof should be valid. Got: " + result);
    }

    @Test
    void rejectTamperedProof() {
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bn254-invalid/proof_tampered.json",
                "/test-vectors/groth16-bn254-invalid/public.json",
                "multiplier");
        var material = loadMaterial(
                "/test-vectors/groth16-bn254-invalid/verification_key.json",
                "multiplier");

        var result = verifier.verify(envelope, material);
        assertFalse(result.proofValid(), "Tampered proof should be rejected");
    }

    @Test
    void rejectWrongPublicInputs() {
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bn254/proof.json",
                "/test-vectors/groth16-bn254-invalid/public_wrong.json",
                "multiplier");
        var material = loadMaterial(
                "/test-vectors/groth16-bn254-invalid/verification_key.json",
                "multiplier");

        var result = verifier.verify(envelope, material);
        assertFalse(result.proofValid(), "Wrong public inputs should be rejected");
    }

    @Test
    void rejectWrongVerificationKey() {
        // Use multiplier proof with cubic VK
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bn254/proof.json",
                "/test-vectors/groth16-bn254/public.json",
                "multiplier");
        var material = loadMaterial(
                "/test-vectors/groth16-bn254-cubic/verification_key.json",
                "cubic");

        var result = verifier.verify(envelope, material);
        assertFalse(result.accepted(), "Wrong VK should be rejected");
    }

    @Test
    void descriptorIsBN254Groth16() {
        var desc = verifier.descriptor();
        assertEquals(ProofSystemId.GROTH16, desc.proofSystem());
        assertEquals(CurveId.BN254, desc.curve());
        assertTrue(desc.supports(ProofSystemId.GROTH16, CurveId.BN254));
        assertFalse(desc.supports(ProofSystemId.GROTH16, CurveId.BLS12_381));
    }

    // --- Helpers ---

    private ZkProofEnvelope loadEnvelope(String proofPath, String publicPath, String circuitName) {
        String proofJson = loadString(proofPath);
        String publicJson = loadString(publicPath);
        String vkPath = proofPath.replace("proof.json", "verification_key.json")
                .replace("proof_tampered.json", "verification_key.json");
        String vkJson = loadString(vkPath);
        return SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, new CircuitId(circuitName));
    }

    private VerificationMaterial loadMaterial(String vkPath, String circuitName) {
        byte[] vkBytes = loadBytes(vkPath);
        return VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BN254, new CircuitId(circuitName));
    }

    private InputStream load(String path) {
        var in = getClass().getResourceAsStream(path);
        if (in == null) fail("Resource not found: " + path);
        return in;
    }

    private byte[] loadBytes(String path) {
        try (var in = load(path)) {
            return in.readAllBytes();
        } catch (Exception e) {
            return fail("Failed to read: " + path);
        }
    }

    private String loadString(String path) {
        try (var in = load(path)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return fail("Failed to read: " + path);
        }
    }
}
