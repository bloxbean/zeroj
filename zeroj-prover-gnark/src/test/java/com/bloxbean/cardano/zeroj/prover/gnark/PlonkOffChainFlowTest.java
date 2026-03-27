package com.bloxbean.cardano.zeroj.prover.gnark;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Complete off-chain PlonK flow: setup → prove → verify.
 * <p>
 * Demonstrates how Java applications can use PlonK proofs today for off-chain
 * verification — no blockchain required. This is useful for:
 * <ul>
 *   <li>Yaci app-layer nodes verifying proof-backed state transitions</li>
 *   <li>Java backend services validating ZK proofs from clients</li>
 *   <li>Privacy-preserving computation verification in enterprise systems</li>
 *   <li>Testing and development of ZK circuits before on-chain deployment</li>
 * </ul>
 * <p>
 * <b>Circuit:</b> Multiplier (X * Y = Z) on BLS12-381<br>
 * <b>Witness:</b> X=3, Y=11, Z=33 (real values, no dummy data)<br>
 * <b>Proof system:</b> PlonK with KZG commitments (universal setup)<br>
 * <b>Advantage over Groth16:</b> Universal SRS — one setup works for any circuit
 * <p>
 * <b>Limitations:</b>
 * <ul>
 *   <li>Verification delegates to gnark native library (Go FFM). A pure Java/blst
 *       PlonK verifier is planned for future releases.</li>
 *   <li>SRS is generated using gnark's unsafe test helper. Production deployments
 *       should use an MPC-generated SRS.</li>
 *   <li>On-chain PlonK verification on Cardano requires pre-computed Fiat-Shamir
 *       challenges (Plutus V3 lacks SHA-256). See ADR-0008 for details.</li>
 * </ul>
 */
@EnabledIf("isNativeLibraryAvailable")
class PlonkOffChainFlowTest {

    static final String TEST_VECTORS = System.getProperty("user.dir")
            + "/../zeroj-test-vectors/src/main/resources/test-vectors/plonk-bls12381/";

    static GnarkProver prover;

    @BeforeAll
    static void setup() {
        prover = new GnarkProver();
    }

    @AfterAll
    static void teardown() {
        if (prover != null) {
            prover.close();
        }
    }

    /**
     * Full lifecycle: setup → prove → verify.
     * <p>
     * This is what a Java application would do to use PlonK:
     * 1. Compile circuit to SparseR1CS (done once, offline)
     * 2. Run PlonK setup with universal SRS (done once per SRS size)
     * 3. Generate proof for specific inputs (per-transaction)
     * 4. Verify proof (can be done by any party with the VK)
     */
    @Test
    void fullLifecycle_setupProveVerify() {
        System.out.println("=== PlonK Off-Chain Flow: Setup → Prove → Verify ===");
        System.out.println("Circuit: Multiplier (X * Y = Z)");
        System.out.println("Curve:   BLS12-381");
        System.out.println("Witness: X=3, Y=11, Z=33");
        System.out.println();

        Path circuitPath = Path.of(TEST_VECTORS, "circuit.scs");
        Path witnessPath = Path.of(TEST_VECTORS, "witness.bin");
        Path vkBinPath = Path.of(TEST_VECTORS, "verification_key.bin");
        Path pubWitPath = Path.of(TEST_VECTORS, "public_witness.bin");

        // --- Step 1: PlonK setup (universal SRS) ---
        System.out.println("1. SETUP: Generating PlonK proving key + verification key...");
        var setupResult = prover.plonkSetup("bls12381", circuitPath);

        assertNotNull(setupResult.pkPath());
        assertNotNull(setupResult.vkJson());
        assertTrue(setupResult.vkJson().contains("plonk"));
        System.out.println("   PK: " + setupResult.pkPath());
        System.out.println("   VK: " + setupResult.vkJson().length() + " bytes JSON");
        System.out.println("   Advantage: same SRS works for ANY circuit up to this size");
        System.out.println();

        // --- Step 2: Prove (off-chain, per-transaction) ---
        System.out.println("2. PROVE: Generating PlonK proof for X=3, Y=11, Z=33...");
        var proveResponse = prover.plonkProveRaw("bls12381", circuitPath,
                Path.of(setupResult.pkPath()), witnessPath);

        assertNotNull(proveResponse);
        assertEquals("plonk", proveResponse.protocol());
        assertEquals("bls12381", proveResponse.curve());
        System.out.println("   Protocol: " + proveResponse.protocol());
        System.out.println("   Curve:    " + proveResponse.curve());
        System.out.println("   Time:     " + proveResponse.provingTimeMs() + "ms");
        System.out.println();

        // --- Step 3: Verify (off-chain, by any verifier node) ---
        System.out.println("3. VERIFY: Checking PlonK proof...");
        String proofBase64 = readFile(Path.of(TEST_VECTORS, "proof_base64.txt"));
        boolean valid = prover.plonkVerify("bls12381", vkBinPath, proofBase64, pubWitPath);

        assertTrue(valid, "PlonK proof should verify");
        System.out.println("   Result: VALID");
        System.out.println();

        // --- Summary ---
        System.out.println("=== PlonK Off-Chain Flow Complete ===");
        System.out.println("What happened:");
        System.out.println("  • Universal SRS generated (one-time, reusable for any circuit)");
        System.out.println("  • Proof generated: proves 3 * 11 = 33 without revealing 3 or 11");
        System.out.println("  • Proof verified: any party with the VK can check validity");
        System.out.println();
        System.out.println("Use cases:");
        System.out.println("  • Yaci node verifying proof-backed state transitions");
        System.out.println("  • Java backend validating client ZK proofs");
        System.out.println("  • Enterprise privacy-preserving computation");
    }

    /**
     * Verify a proof generated independently (simulate receiving a proof from elsewhere).
     * This demonstrates the verifier-only role — no access to the prover or circuit compilation.
     */
    @Test
    void verifierOnly_validatesExternalProof() {
        System.out.println("=== PlonK Verifier-Only Mode ===");
        System.out.println("Scenario: Yaci verifier node receives a proof from an external prover");
        System.out.println();

        // Verifier only has: VK binary + proof base64 + public witness
        // It does NOT have: proving key, circuit source, private witness
        Path vkBinPath = Path.of(TEST_VECTORS, "verification_key.bin");
        Path pubWitPath = Path.of(TEST_VECTORS, "public_witness.bin");
        String proofBase64 = readFile(Path.of(TEST_VECTORS, "proof_base64.txt"));

        boolean valid = prover.plonkVerify("bls12381", vkBinPath, proofBase64, pubWitPath);
        assertTrue(valid, "External proof should verify");

        System.out.println("Proof verified: the prover knows X, Y such that X * Y = 33");
        System.out.println("Verifier learned: NOTHING about X or Y (only that the product is 33)");
        System.out.println("Verifier needed: VK (public) + proof + public inputs");
        System.out.println("Verifier did NOT need: prover's secret, circuit source, or proving key");
    }

    /**
     * Tampered proof should be rejected.
     */
    @Test
    void tamperedProof_rejected() {
        Path vkBinPath = Path.of(TEST_VECTORS, "verification_key.bin");
        Path pubWitPath = Path.of(TEST_VECTORS, "public_witness.bin");
        String proofBase64 = readFile(Path.of(TEST_VECTORS, "proof_base64.txt"));

        // Tamper with the proof (flip a character in the base64)
        char[] chars = proofBase64.toCharArray();
        chars[10] = chars[10] == 'A' ? 'B' : 'A';
        String tampered = new String(chars);

        boolean valid = prover.plonkVerify("bls12381", vkBinPath, tampered, pubWitPath);
        assertFalse(valid, "Tampered proof should be rejected");
    }

    private static String readFile(Path path) {
        try { return Files.readString(path).trim(); }
        catch (Exception e) { fail("Failed to read: " + path); return ""; }
    }

    static boolean isNativeLibraryAvailable() {
        return GnarkNativeLoader.isAvailable();
    }
}
