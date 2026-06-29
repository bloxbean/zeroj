package com.bloxbean.cardano.zeroj.ccl;

import com.bloxbean.cardano.client.metadata.Metadata;
import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.cardano.AnchorPattern;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.*;

class ZkTransactionHelperTest {

    private static final byte[] PROOF_HASH = sha256("test-proof".getBytes());
    private static final byte[] STATE_ROOT = sha256("state-root".getBytes());
    private static final byte[] VK_HASH = sha256("verification-key".getBytes());
    private static final byte[] NULLIFIER = sha256("nullifier".getBytes());

    @Test
    void anchorProofHash_buildsMetadata() {
        Metadata metadata = ZkTransactionHelper.anchorProofHash(PROOF_HASH)
                .buildMetadata();

        assertNotNull(metadata);
        byte[] cbor = metadata.serialize();
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);
    }

    @Test
    void anchorStateRoot_buildsMetadata() {
        Metadata metadata = ZkTransactionHelper.anchorStateRoot(STATE_ROOT, PROOF_HASH)
                .buildMetadata();

        assertNotNull(metadata);
        assertEquals(AnchorPattern.STATE_ROOT_AND_PROOF_HASH,
                ZkTransactionHelper.anchorStateRoot(STATE_ROOT, PROOF_HASH).anchor().pattern());
    }

    @Test
    void anchorFullRef_buildsMetadata() {
        Metadata metadata = ZkTransactionHelper.anchorFullRef(STATE_ROOT, PROOF_HASH, "multiplier", VK_HASH)
                .buildMetadata();

        assertNotNull(metadata);
        assertEquals(AnchorPattern.FULL_VERIFICATION_REF,
                ZkTransactionHelper.anchorFullRef(STATE_ROOT, PROOF_HASH, "multiplier", VK_HASH).anchor().pattern());
    }

    @Test
    void anchorNullifier_buildsMetadata() {
        Metadata metadata = ZkTransactionHelper.anchorNullifier(NULLIFIER, PROOF_HASH)
                .buildMetadata();

        assertNotNull(metadata);
        assertEquals(AnchorPattern.NULLIFIER_COMMITMENT,
                ZkTransactionHelper.anchorNullifier(NULLIFIER, PROOF_HASH).anchor().pattern());
    }

    @Test
    void customLabel() {
        Metadata metadata = ZkTransactionHelper.anchorProofHash(PROOF_HASH)
                .withLabel(42)
                .buildMetadata();

        assertNotNull(metadata);
    }

    @Test
    void metadataIsDeterministic() {
        var helper = ZkTransactionHelper.anchorFullRef(STATE_ROOT, PROOF_HASH, "circuit-1", VK_HASH);

        byte[] cbor1 = helper.buildMetadata().serialize();
        byte[] cbor2 = helper.buildMetadata().serialize();

        assertArrayEquals(cbor1, cbor2, "Metadata serialization must be deterministic");
    }

    @Test
    void validateAndBuildMetadata_validProof_succeeds() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        String publicJson = loadString("/test-vectors/groth16-bls12381/public.json");

        var registry = VerifierRegistry.empty();
        registry.register(new Groth16BLS12381PureJavaVerifier());
        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("multiplier"));
        vkRegistry.register(material);
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
                new CircuitId("multiplier"));

        // Should succeed — valid proof
        Metadata metadata = ZkTransactionHelper.anchorProofHash(PROOF_HASH)
                .validateAndBuildMetadata(envelope, material, orchestrator);
        assertNotNull(metadata);
    }

    @Test
    void validateAndBuildMetadata_invalidProof_throws() {
        String proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");

        var registry = VerifierRegistry.empty();
        registry.register(new Groth16BLS12381PureJavaVerifier());
        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("multiplier"));
        vkRegistry.register(material);
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        // Wrong public inputs → proof invalid
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson,
                "[\"999\", \"888\"]", new CircuitId("multiplier"));

        assertThrows(IllegalStateException.class, () ->
                ZkTransactionHelper.anchorProofHash(PROOF_HASH)
                        .validateAndBuildMetadata(envelope, material, orchestrator));
    }

    private static String loadString(String path) {
        try (var in = ZkTransactionHelperTest.class.getResourceAsStream(path)) {
            if (in == null) throw new RuntimeException("Resource not found: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
