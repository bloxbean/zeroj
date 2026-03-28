package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for snarkjs PlonK JSON codec using real snarkjs-generated test vectors.
 */
class SnarkjsPlonkCodecTest {

    private String loadString(String resource) {
        try (var in = getClass().getResourceAsStream(resource)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load: " + resource, e);
        }
    }

    // --- Proof parsing ---

    @Test
    void parseProof_realSnarkjsVector() {
        var proofJson = loadString("/test-vectors/plonk-bn254/proof.json");
        var proof = SnarkjsPlonkCodec.parseProof(proofJson);

        assertNotNull(proof);
        assertEquals("plonk", proof.protocol());
        assertEquals("bn128", proof.curve());

        // A, B, C commitments should be G1 points with 3 coordinates
        assertEquals(3, proof.A().size());
        assertEquals(3, proof.B().size());
        assertEquals(3, proof.C().size());
        assertEquals(BigInteger.ONE, proof.A().get(2)); // z=1 (affine)

        // Z, T1-T3 commitments
        assertEquals(3, proof.Z().size());
        assertEquals(3, proof.T1().size());
        assertEquals(3, proof.T2().size());
        assertEquals(3, proof.T3().size());

        // Scalar evaluations should be non-null and in the field
        assertNotNull(proof.evalA());
        assertNotNull(proof.evalB());
        assertNotNull(proof.evalC());
        assertNotNull(proof.evalS1());
        assertNotNull(proof.evalS2());
        assertNotNull(proof.evalZw());
        assertTrue(proof.evalA().signum() > 0);
        assertTrue(proof.evalB().signum() > 0);

        // Opening proofs
        assertEquals(3, proof.Wxi().size());
        assertEquals(3, proof.Wxiw().size());
    }

    @Test
    void parseProof_fromInputStream() {
        var in = getClass().getResourceAsStream("/test-vectors/plonk-bn254/proof.json");
        var proof = SnarkjsPlonkCodec.parseProof(in);
        assertNotNull(proof);
        assertEquals("plonk", proof.protocol());
    }

    @Test
    void parseProof_invalidJson_throws() {
        assertThrows(CodecException.class, () -> SnarkjsPlonkCodec.parseProof("not json"));
    }

    @Test
    void parseProof_missingField_throws() {
        assertThrows(CodecException.class, () -> SnarkjsPlonkCodec.parseProof("{\"A\":[1,2,3]}"));
    }

    // --- Verification key parsing ---

    @Test
    void parseVerificationKey_realSnarkjsVector() {
        var vkJson = loadString("/test-vectors/plonk-bn254/verification_key.json");
        var vk = SnarkjsPlonkCodec.parseVerificationKey(vkJson);

        assertNotNull(vk);
        assertEquals("plonk", vk.protocol());
        assertEquals("bn128", vk.curve());
        assertEquals(2, vk.nPublic());
        assertEquals(3, vk.power());
        assertEquals(8, vk.domainSize()); // 2^3

        // Coset generators
        assertEquals(new BigInteger("2"), vk.k1());
        assertEquals(new BigInteger("3"), vk.k2());

        // Selector commitments (G1 points)
        assertEquals(3, vk.Qm().size());
        assertEquals(3, vk.Ql().size());
        assertEquals(3, vk.Qr().size());
        assertEquals(3, vk.Qo().size());
        assertEquals(3, vk.Qc().size());

        // Permutation commitments
        assertEquals(3, vk.S1().size());
        assertEquals(3, vk.S2().size());
        assertEquals(3, vk.S3().size());

        // SRS G2 point
        assertEquals(3, vk.X_2().size()); // 3 Fp2 pairs
        assertEquals(2, vk.X_2().get(0).size()); // each Fp2 has 2 elements

        // Root of unity
        assertNotNull(vk.w());
        assertTrue(vk.w().signum() > 0);
    }

    @Test
    void parseVerificationKey_fromInputStream() {
        var in = getClass().getResourceAsStream("/test-vectors/plonk-bn254/verification_key.json");
        var vk = SnarkjsPlonkCodec.parseVerificationKey(in);
        assertNotNull(vk);
        assertEquals("plonk", vk.protocol());
    }

    @Test
    void parseVerificationKey_invalidJson_throws() {
        assertThrows(CodecException.class, () -> SnarkjsPlonkCodec.parseVerificationKey("not json"));
    }

    // --- Envelope construction ---

    @Test
    void toEnvelopeFromJson_buildsCorrectEnvelope() {
        var proofJson = loadString("/test-vectors/plonk-bn254/proof.json");
        var vkJson = loadString("/test-vectors/plonk-bn254/verification_key.json");
        var publicJson = loadString("/test-vectors/plonk-bn254/public.json");

        var envelope = SnarkjsPlonkCodec.toEnvelopeFromJson(
                proofJson, vkJson, publicJson, new CircuitId("multiplier"));

        assertEquals(ProofSystemId.PLONK, envelope.proofSystem());
        assertEquals(com.bloxbean.cardano.zeroj.api.CurveId.BN254, envelope.curve());
        assertEquals("multiplier", envelope.circuitId().value());
        assertEquals(2, envelope.publicInputs().size());
        assertEquals(new BigInteger("33"), envelope.publicInputs().get(0));
        assertEquals(new BigInteger("3"), envelope.publicInputs().get(1));
        assertEquals("snarkjs-plonk-json", envelope.proofFormat().orElse(null));
        assertTrue(envelope.proofBytes().length > 0);
    }

    // --- Cross-check: proof values are in the BN254 scalar field ---

    @Test
    void proofEvaluations_areInBN254Field() {
        var proofJson = loadString("/test-vectors/plonk-bn254/proof.json");
        var proof = SnarkjsPlonkCodec.parseProof(proofJson);

        BigInteger bn254_r = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");

        // All evaluations must be < field modulus
        assertTrue(proof.evalA().compareTo(bn254_r) < 0, "evalA exceeds field");
        assertTrue(proof.evalB().compareTo(bn254_r) < 0, "evalB exceeds field");
        assertTrue(proof.evalC().compareTo(bn254_r) < 0, "evalC exceeds field");
        assertTrue(proof.evalS1().compareTo(bn254_r) < 0, "evalS1 exceeds field");
        assertTrue(proof.evalS2().compareTo(bn254_r) < 0, "evalS2 exceeds field");
        assertTrue(proof.evalZw().compareTo(bn254_r) < 0, "evalZw exceeds field");
    }

    @Test
    void vkRootOfUnity_hasCorrectOrder() {
        var vkJson = loadString("/test-vectors/plonk-bn254/verification_key.json");
        var vk = SnarkjsPlonkCodec.parseVerificationKey(vkJson);

        BigInteger bn254_r = new BigInteger(
                "21888242871839275222246405745257275088548364400416034343698204186575808495617");

        // omega^n should equal 1 mod r
        BigInteger omegaN = vk.w().modPow(BigInteger.valueOf(vk.domainSize()), bn254_r);
        assertEquals(BigInteger.ONE, omegaN, "omega^n must equal 1 in Fr");
    }
}
