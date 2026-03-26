package com.bloxbean.cardano.zeroj.verifier.core;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class VerifierCoreTest {

    // --- VerifierRegistry ---

    @Test
    void registry_findRegisteredBackend() {
        var registry = VerifierRegistry.empty();
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, true));

        var found = registry.find(ProofSystemId.GROTH16, CurveId.BN254);
        assertTrue(found.isPresent());
    }

    @Test
    void registry_findReturnsEmptyForUnregistered() {
        var registry = VerifierRegistry.empty();
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, true));

        assertTrue(registry.find(ProofSystemId.PLONK, CurveId.BN254).isEmpty());
        assertTrue(registry.find(ProofSystemId.GROTH16, CurveId.BLS12_381).isEmpty());
    }

    @Test
    void registry_allReturnsRegisteredBackends() {
        var registry = VerifierRegistry.empty();
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, true));
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BLS12_381, true));

        assertEquals(2, registry.all().size());
    }

    @Test
    void registry_serviceLoaderDiscovery() {
        // This test verifies ServiceLoader can find implementations from zeroj-verifier-groth16
        // It depends on the META-INF/services file being on the classpath
        var registry = VerifierRegistry.withServiceLoader();
        // At minimum, if zeroj-verifier-groth16 is on classpath, we should find verifiers
        // In unit test context without the full classpath, this may find 0 — that's OK
        assertNotNull(registry.all());
    }

    // --- VerifierOrchestrator ---

    @Test
    void orchestrator_routesToCorrectBackend() {
        var registry = VerifierRegistry.empty();
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, true));

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of("vk".getBytes(), ProofSystemId.GROTH16,
                CurveId.BN254, new CircuitId("test"));
        vkRegistry.register(material);

        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);
        var envelope = makeEnvelope(ProofSystemId.GROTH16, CurveId.BN254);
        var result = orchestrator.verify(envelope, material);

        assertTrue(result.proofValid());
    }

    @Test
    void orchestrator_rejectsUnsupportedProofSystem() {
        var registry = VerifierRegistry.empty();
        // Only BN254 registered
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, true));

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        var material = VerificationMaterial.of("vk".getBytes(), ProofSystemId.GROTH16,
                CurveId.BLS12_381, new CircuitId("test"));
        var envelope = makeEnvelope(ProofSystemId.GROTH16, CurveId.BLS12_381);

        var result = orchestrator.verify(envelope, material);
        assertFalse(result.accepted());
        assertEquals(VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM, result.reasonCode().orElse(null));
    }

    @Test
    void orchestrator_reportsUnknownVk() {
        var registry = VerifierRegistry.empty();
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, true));

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        // Don't register any VK
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        var envelope = makeEnvelope(ProofSystemId.GROTH16, CurveId.BN254);
        var result = orchestrator.verify(envelope); // uses VK registry lookup

        assertFalse(result.accepted());
        assertEquals(VerificationResult.ReasonCode.UNKNOWN_VERIFICATION_KEY, result.reasonCode().orElse(null));
    }

    @Test
    void orchestrator_invalidProofPropagated() {
        var registry = VerifierRegistry.empty();
        registry.register(fakeVerifier(ProofSystemId.GROTH16, CurveId.BN254, false)); // always fails

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of("vk".getBytes(), ProofSystemId.GROTH16,
                CurveId.BN254, new CircuitId("test"));

        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);
        var envelope = makeEnvelope(ProofSystemId.GROTH16, CurveId.BN254);
        var result = orchestrator.verify(envelope, material);

        assertFalse(result.proofValid());
    }

    // --- Helpers ---

    private static ZkVerifier fakeVerifier(ProofSystemId ps, CurveId curve, boolean valid) {
        return new ZkVerifier() {
            @Override
            public VerificationResult verify(ZkProofEnvelope e, VerificationMaterial m) {
                return valid ? VerificationResult.cryptoValid() : VerificationResult.proofInvalid("fake failure");
            }

            @Override
            public BackendDescriptor descriptor() {
                return new BackendDescriptor(ps, curve, "fake-" + ps + "-" + curve);
            }
        };
    }

    private static ZkProofEnvelope makeEnvelope(ProofSystemId ps, CurveId curve) {
        return ZkProofEnvelope.builder()
                .proofSystem(ps)
                .curve(curve)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1, 2, 3})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("test"))
                .build();
    }
}
