package com.bloxbean.cardano.zeroj.verifier.groth16.bls12381;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.codec.CodecException;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests the pure Java Groth16 BLS12-381 verifier using the same test vectors
 * as the blst-based verifier, ensuring identical results.
 */
class Groth16BLS12381PureJavaVerifierTest {

    private static final BigInteger FR = G1Point.R;
    private static final BigInteger FP = Fp.P;

    private final Groth16BLS12381PureJavaVerifier verifier = new Groth16BLS12381PureJavaVerifier();

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
        assertTrue(result.proofValid(), "Pure Java BLS12-381 proof should be valid. Got: " + result);
    }

    @Test
    void descriptorIsBLS12381Groth16Java() {
        var desc = verifier.descriptor();
        assertEquals(ProofSystemId.GROTH16, desc.proofSystem());
        assertEquals(CurveId.BLS12_381, desc.curve());
        assertEquals("groth16-bls12381-java", desc.name());
    }

    @Test
    void rejectWrongPublicInputs() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        // Wrong public inputs (different values)
        var wrongInputs = new PublicInputs(java.util.List.of(java.math.BigInteger.valueOf(999)));
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("multiplier-bls"))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .publicInputs(wrongInputs)
                .vkRef(new VerificationKeyRef.ByHash(new byte[32]))
                .proofFormat("snarkjs-json")
                .build();
        var material = loadMaterial("/test-vectors/groth16-bls12381/verification_key.json", "multiplier-bls");

        var result = verifier.verify(envelope, material);
        assertFalse(result.proofValid(), "Wrong public inputs should fail");
    }

    @Test
    void rejectsPublicInputEqualOrAboveScalarField() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        String publicJson = loadString("/test-vectors/groth16-bls12381/public.json");
        var inputs = SnarkjsJsonCodec.parsePublicInputs(publicJson);
        String malformedPublicJson = replaceFirstDecimal(publicJson, inputs.get(0), inputs.get(0).add(FR));
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                proofJson, vkJson, malformedPublicJson, new CircuitId("multiplier-bls"));
        var material = loadMaterial("/test-vectors/groth16-bls12381/verification_key.json", "multiplier-bls");

        var result = verifier.verify(envelope, material);
        assertFalse(result.proofValid(), "Public input >= scalar field order must fail");
        assertEquals(VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS, result.reasonCode().orElseThrow());
    }

    @Test
    void rejectsNegativePublicInput() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        String publicJson = loadString("/test-vectors/groth16-bls12381/public.json");
        var inputs = SnarkjsJsonCodec.parsePublicInputs(publicJson);
        String malformedPublicJson = replaceFirstDecimal(publicJson, inputs.get(0), BigInteger.ONE.negate());
        assertThrows(CodecException.class, () -> SnarkjsJsonCodec.toEnvelopeFromJson(
                proofJson, vkJson, malformedPublicJson, new CircuitId("multiplier-bls")));
    }

    @Test
    void rejectsNonCanonicalProofCoordinate() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String publicJson = loadString("/test-vectors/groth16-bls12381/public.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        var proof = SnarkjsJsonCodec.parseProof(proofJson);
        String malformedProofJson = replaceFirstDecimal(proofJson, proof.piA().get(0), proof.piA().get(0).add(FP));
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                malformedProofJson, vkJson, publicJson, new CircuitId("multiplier-bls"));
        var material = loadMaterial("/test-vectors/groth16-bls12381/verification_key.json", "multiplier-bls");

        var result = verifier.verify(envelope, material);
        assertFalse(result.proofValid(), "Non-canonical proof coordinate must fail");
        assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, result.reasonCode().orElseThrow());
    }

    @Test
    void rejectsInfinityProofPoint() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String publicJson = loadString("/test-vectors/groth16-bls12381/public.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        String malformedProofJson = replaceFirstDecimal(proofJson, BigInteger.ONE, BigInteger.ZERO);
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                malformedProofJson, vkJson, publicJson, new CircuitId("multiplier-bls"));
        var material = loadMaterial("/test-vectors/groth16-bls12381/verification_key.json", "multiplier-bls");

        var result = verifier.verify(envelope, material);
        assertFalse(result.proofValid(), "Proof point at infinity must fail");
        assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, result.reasonCode().orElseThrow());
    }

    @Test
    void matchesBlstVerifierResult() {
        var envelope = loadEnvelope(
                "/test-vectors/groth16-bls12381/proof.json",
                "/test-vectors/groth16-bls12381/public.json",
                "multiplier-bls");
        var material = loadMaterial(
                "/test-vectors/groth16-bls12381/verification_key.json",
                "multiplier-bls");

        var pureJavaResult = verifier.verify(envelope, material);
        var blstResult = new Groth16BLS12381Verifier().verify(envelope, material);

        assertEquals(blstResult.proofValid(), pureJavaResult.proofValid(),
                "Pure Java and blst verifiers must agree");
        assertTrue(pureJavaResult.proofValid());
    }

    // --- Helpers ---

    private ZkProofEnvelope loadEnvelope(String proofPath, String publicPath, String circuitName) {
        String proofJson = loadString(proofPath);
        String publicJson = loadString(publicPath);
        String vkJson = loadString(proofPath.replace("proof.json", "verification_key.json"));
        return SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, new CircuitId(circuitName));
    }

    private VerificationMaterial loadMaterial(String vkPath, String circuitName) {
        return VerificationMaterial.of(loadBytes(vkPath), ProofSystemId.GROTH16,
                CurveId.BLS12_381, new CircuitId(circuitName));
    }

    private byte[] loadBytes(String path) {
        try (var in = getClass().getResourceAsStream(path)) { return in.readAllBytes(); }
        catch (Exception e) { return fail("Failed to read: " + path); }
    }

    private String loadString(String path) {
        try (var in = getClass().getResourceAsStream(path)) { return new String(in.readAllBytes(), StandardCharsets.UTF_8); }
        catch (Exception e) { return fail("Failed to read: " + path); }
    }

    private static String replaceFirstDecimal(String json, BigInteger oldValue, BigInteger newValue) {
        return json.replaceFirst(
                Pattern.quote("\"" + oldValue + "\""),
                "\"" + newValue + "\"");
    }
}
