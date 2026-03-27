package com.bloxbean.cardano.zeroj.prover.gnark;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.GnarkPlonkCodec;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test: PlonK proofs routing through VerifierOrchestrator via SPI.
 * <p>
 * Demonstrates that PlonK proofs can be verified using the same orchestrator
 * and SPI infrastructure as Groth16 — no application code changes needed.
 */
@EnabledIf("isNativeLibraryAvailable")
class PlonkSpiIntegrationTest {

    static final String TEST_VECTORS = System.getProperty("user.dir")
            + "/../zeroj-test-vectors/src/main/resources/test-vectors/plonk-bls12381/";

    @Test
    void plonkProof_routesThroughOrchestrator() throws Exception {
        // 1. Register PlonK verifier backend
        var registry = VerifierRegistry.empty();
        var gnarkLib = new GnarkLibrary();
        registry.register(new PlonkGnarkVerifier(gnarkLib));

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        // 2. Build ZkProofEnvelope from gnark PlonK JSON
        String proofJson = Files.readString(Path.of(TEST_VECTORS, "proof.json"), StandardCharsets.UTF_8);
        String vkJson = Files.readString(Path.of(TEST_VECTORS, "verification_key.json"), StandardCharsets.UTF_8);
        String publicJson = Files.readString(Path.of(TEST_VECTORS, "public.json"), StandardCharsets.UTF_8);

        ZkProofEnvelope envelope = GnarkPlonkCodec.toEnvelopeFromJson(
                proofJson, vkJson, publicJson, new CircuitId("plonk-multiplier"));

        assertEquals(ProofSystemId.PLONK, envelope.proofSystem());
        assertEquals(CurveId.BLS12_381, envelope.curve());

        // 3. Create VerificationMaterial with gnark binary VK
        //    Convention: vkHash carries the public witness binary (for gnark FFM verifier)
        byte[] vkBinaryBytes = Files.readAllBytes(Path.of(TEST_VECTORS, "verification_key.bin"));
        byte[] pubWitBytes = Files.readAllBytes(Path.of(TEST_VECTORS, "public_witness.bin"));
        var material = VerificationMaterial.of(vkBinaryBytes,
                ProofSystemId.PLONK, CurveId.BLS12_381, new CircuitId("plonk-multiplier"),
                pubWitBytes);

        // 4. Verify through orchestrator — routes to PlonkGnarkVerifier via SPI
        VerificationResult result = orchestrator.verify(envelope, material);

        assertTrue(result.proofValid(),
                "PlonK proof should verify through orchestrator: " + result.message().orElse(""));

        System.out.println("PlonK proof verified via VerifierOrchestrator (SPI routing)");
        System.out.println("  ProofSystem: " + envelope.proofSystem());
        System.out.println("  Curve: " + envelope.curve());
        System.out.println("  Public inputs: " + envelope.publicInputs().values());
        System.out.println("  Result: " + (result.proofValid() ? "VALID" : "INVALID"));

        gnarkLib.close();
    }

    @Test
    void plonkProof_wrongVk_fails() throws Exception {
        var registry = VerifierRegistry.empty();
        var gnarkLib = new GnarkLibrary();
        registry.register(new PlonkGnarkVerifier(gnarkLib));
        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        String proofJson = Files.readString(Path.of(TEST_VECTORS, "proof.json"), StandardCharsets.UTF_8);
        String publicJson = Files.readString(Path.of(TEST_VECTORS, "public.json"), StandardCharsets.UTF_8);
        // Use proof.json as "wrong VK" — will fail binary VK parsing
        ZkProofEnvelope envelope = GnarkPlonkCodec.toEnvelopeFromJson(
                proofJson, proofJson, publicJson, new CircuitId("plonk-multiplier"));

        // Wrong VK bytes → verification should fail
        var material = VerificationMaterial.of(new byte[]{1, 2, 3},
                ProofSystemId.PLONK, CurveId.BLS12_381, new CircuitId("plonk-multiplier"));

        VerificationResult result = orchestrator.verify(envelope, material);
        assertFalse(result.proofValid(), "Wrong VK should fail");

        gnarkLib.close();
    }

    static boolean isNativeLibraryAvailable() {
        return GnarkNativeLoader.isAvailable();
    }
}
