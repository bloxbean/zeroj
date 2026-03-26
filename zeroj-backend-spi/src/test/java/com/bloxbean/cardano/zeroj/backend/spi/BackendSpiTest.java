package com.bloxbean.cardano.zeroj.backend.spi;

import com.bloxbean.cardano.zeroj.api.*;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class BackendSpiTest {

    // --- BackendDescriptor ---

    @Test
    void descriptor_supportsMatchingCombination() {
        var desc = new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BN254, "test-backend");
        assertTrue(desc.supports(ProofSystemId.GROTH16, CurveId.BN254));
    }

    @Test
    void descriptor_rejectsNonMatchingCurve() {
        var desc = new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BN254, "test-backend");
        assertFalse(desc.supports(ProofSystemId.GROTH16, CurveId.BLS12_381));
    }

    @Test
    void descriptor_rejectsNonMatchingProofSystem() {
        var desc = new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BN254, "test-backend");
        assertFalse(desc.supports(ProofSystemId.PLONK, CurveId.BN254));
    }

    // --- InMemoryVerificationKeyRegistry ---

    @Test
    void vkRegistry_registerAndLookupByHash() {
        var registry = new InMemoryVerificationKeyRegistry();
        byte[] vkBytes = "test-vk-data".getBytes();
        byte[] vkHash = sha256(vkBytes);
        var material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BN254,
                new CircuitId("test-circuit"), vkHash);

        registry.register(material);

        var found = registry.lookup(new VerificationKeyRef.ByHash(vkHash));
        assertTrue(found.isPresent());
        assertArrayEquals(vkBytes, found.get().vkBytes());
    }

    @Test
    void vkRegistry_registerAndLookupById() {
        var registry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of("vk-data".getBytes(), ProofSystemId.GROTH16,
                CurveId.BN254, new CircuitId("my-circuit"));

        registry.register(material);

        // Should be findable by circuit ID
        var found = registry.lookup(new VerificationKeyRef.ById("my-circuit"));
        assertTrue(found.isPresent());
    }

    @Test
    void vkRegistry_lookupMissingReturnsEmpty() {
        var registry = new InMemoryVerificationKeyRegistry();
        assertTrue(registry.lookup(new VerificationKeyRef.ById("nonexistent")).isEmpty());
        assertTrue(registry.lookup(new VerificationKeyRef.ByHash(new byte[32])).isEmpty());
    }

    @Test
    void vkRegistry_multipleRegistrations() {
        var registry = new InMemoryVerificationKeyRegistry();
        registry.register(VerificationMaterial.of("vk-1".getBytes(), ProofSystemId.GROTH16,
                CurveId.BN254, new CircuitId("circuit-a")));
        registry.register(VerificationMaterial.of("vk-2".getBytes(), ProofSystemId.GROTH16,
                CurveId.BLS12_381, new CircuitId("circuit-b")));

        assertTrue(registry.lookup(new VerificationKeyRef.ById("circuit-a")).isPresent());
        assertTrue(registry.lookup(new VerificationKeyRef.ById("circuit-b")).isPresent());
    }

    private static byte[] sha256(byte[] data) {
        try { return java.security.MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
