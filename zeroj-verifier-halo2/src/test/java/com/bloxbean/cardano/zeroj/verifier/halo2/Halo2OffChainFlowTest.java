package com.bloxbean.cardano.zeroj.verifier.halo2;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.Halo2Codec;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Complete off-chain Halo2 flow: setup → prove → codec → SPI verify → orchestrator.
 * <p>
 * Demonstrates how Java applications (including Yaci app-layer plugins) can use
 * Halo2 IPA proofs today for off-chain verification — no blockchain required.
 * <p>
 * <b>Key advantage:</b> Halo2 IPA requires NO trusted setup. The commitment parameters
 * are transparent (deterministic, publicly verifiable). Unlike Groth16 (per-circuit ceremony)
 * or PlonK (universal SRS), IPA has zero trust assumptions.
 * <p>
 * <b>Use cases:</b>
 * <ul>
 *   <li>Yaci app-layer node plugins verifying proof-backed state transitions</li>
 *   <li>Java backend services validating ZK proofs from clients</li>
 *   <li>Privacy-preserving computation in enterprise systems</li>
 *   <li>Recursive proof aggregation (Halo2 IPA supports native recursion)</li>
 * </ul>
 */
@EnabledIf("isNativeLibraryAvailable")
class Halo2OffChainFlowTest {

    static Halo2Library library;

    @BeforeAll
    static void setup() throws Exception {
        library = new Halo2Library();
    }

    /**
     * Full off-chain lifecycle: setup → prove → codec → verify via SPI → orchestrator.
     * This is the flow a Yaci node plugin would use.
     */
    @Test
    void fullLifecycle_proveCodecVerifyOrchestrator() {
        System.out.println("=== Halo2 Off-Chain E2E: Prove → Codec → Verify via Orchestrator ===");
        System.out.println("Circuit:    Multiplier (3 * 11 = 33)");
        System.out.println("Commitment: IPA (Inner Product Argument)");
        System.out.println("Curve:      Pallas (Pasta cycle)");
        System.out.println("Setup:      NONE (transparent — no ceremony!)");
        System.out.println();

        // 1. PROVE: generate Halo2 proof via Rust FFM
        System.out.println("1. PROVE: Generating Halo2 IPA proof...");
        String resultJson = library.setupAndProve(4, 3, 11);
        assertNotNull(resultJson);
        assertTrue(Halo2Codec.wasVerified(resultJson), "Proof should be verified in Rust");
        System.out.println("   Proof generated and verified in Rust");

        // 2. CODEC: parse into ZkProofEnvelope
        System.out.println("2. CODEC: Parsing into ZkProofEnvelope...");
        ZkProofEnvelope envelope = Halo2Codec.toEnvelopeFromJson(
                resultJson, new CircuitId("halo2-multiplier"));

        assertEquals(ProofSystemId.HALO2, envelope.proofSystem());
        assertEquals(CurveId.PALLAS, envelope.curve());
        assertEquals(1, envelope.publicInputs().size());
        assertEquals(BigInteger.valueOf(33), envelope.publicInputs().values().getFirst());
        System.out.println("   Envelope: proofSystem=" + envelope.proofSystem()
                + ", curve=" + envelope.curve()
                + ", publicInputs=" + envelope.publicInputs().values());

        // 3. ORCHESTRATOR: verify through SPI routing
        System.out.println("3. VERIFY: Routing through VerifierOrchestrator...");
        var registry = VerifierRegistry.empty();
        registry.register(new Halo2Verifier(library));
        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var orchestrator = new VerifierOrchestrator(registry, vkRegistry);

        var material = VerificationMaterial.of(new byte[]{1},
                ProofSystemId.HALO2, CurveId.PALLAS, new CircuitId("halo2-multiplier"));

        VerificationResult result = orchestrator.verify(envelope, material);
        assertTrue(result.proofValid(),
                "Halo2 proof should verify through orchestrator: " + result.message().orElse(""));
        System.out.println("   Result: VALID");

        // 4. SUMMARY
        System.out.println();
        System.out.println("=== Halo2 Off-Chain E2E Complete ===");
        System.out.println("Flow: Rust Prover → Halo2Codec → ZkProofEnvelope → VerifierOrchestrator → Halo2Verifier → VALID");
        System.out.println();
        System.out.println("What this demonstrates:");
        System.out.println("  • Halo2 IPA proof generation and verification in Java via Rust FFM");
        System.out.println("  • Standard ZeroJ codec pipeline (same as Groth16/PlonK)");
        System.out.println("  • SPI-based backend routing (VerifierOrchestrator selects Halo2Verifier)");
        System.out.println("  • NO trusted setup — IPA commitment is fully transparent");
        System.out.println();
        System.out.println("Yaci app-layer usage:");
        System.out.println("  • Plugin receives proof-backed state transition");
        System.out.println("  • Parses with Halo2Codec.toEnvelopeFromJson()");
        System.out.println("  • Verifies via VerifierOrchestrator.verify()");
        System.out.println("  • Accepts/rejects transition based on result.proofValid()");
    }

    /**
     * Multiple circuits with different inputs — each generates a fresh proof.
     */
    @Test
    void multipleProofs_allVerify() {
        var registry = VerifierRegistry.empty();
        registry.register(new Halo2Verifier(library));
        var orchestrator = new VerifierOrchestrator(registry, new InMemoryVerificationKeyRegistry());

        // Verify 3 different multiplications
        int[][] inputs = {{3, 11}, {7, 5}, {2, 19}};
        for (int[] ab : inputs) {
            String json = library.setupAndProve(4, ab[0], ab[1]);
            var envelope = Halo2Codec.toEnvelopeFromJson(json, new CircuitId("mul"));
            var material = VerificationMaterial.of(new byte[]{1},
                    ProofSystemId.HALO2, CurveId.PALLAS, new CircuitId("mul"));

            VerificationResult result = orchestrator.verify(envelope, material);
            assertTrue(result.proofValid(),
                    ab[0] + " * " + ab[1] + " should verify");
            System.out.println("Verified: " + ab[0] + " * " + ab[1] + " = " + (ab[0] * ab[1]));
        }
    }

    /**
     * Tampered proof bytes should fail verification.
     */
    @Test
    void tamperedProof_failsVerification() throws Exception {
        String json = library.setupAndProve(4, 3, 11);
        var root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        String proofBase64 = root.get("proof").asText();
        byte[] proofBytes = java.util.Base64.getDecoder().decode(proofBase64);
        byte[] paramsBase64Bytes = java.util.Base64.getDecoder().decode(root.get("params").asText());

        // Tamper proof
        proofBytes[10] ^= (byte) 0xFF;

        boolean valid = library.verify(paramsBase64Bytes, new byte[0], proofBytes, "[\"33\"]");
        assertFalse(valid, "Tampered proof should fail");
    }

    /**
     * Wrong public input should fail verification.
     */
    @Test
    void wrongPublicInput_failsVerification() throws Exception {
        String json = library.setupAndProve(4, 3, 11);
        var root = new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        byte[] proofBytes = java.util.Base64.getDecoder().decode(root.get("proof").asText());
        byte[] paramsBytes = java.util.Base64.getDecoder().decode(root.get("params").asText());

        // Wrong public input: 99 instead of 33
        boolean valid = library.verify(paramsBytes, new byte[0], proofBytes, "[\"99\"]");
        assertFalse(valid, "Wrong public input should fail");
    }

    static boolean isNativeLibraryAvailable() {
        return Halo2NativeLoader.isAvailable();
    }
}
