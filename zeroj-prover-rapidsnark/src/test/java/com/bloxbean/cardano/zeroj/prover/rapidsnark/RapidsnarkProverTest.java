package com.bloxbean.cardano.zeroj.prover.rapidsnark;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.codec.SnarkjsProof;
import com.bloxbean.cardano.zeroj.prover.sidecar.ProveResponse;
import com.bloxbean.cardano.zeroj.prover.sidecar.ProverException;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Groth16BN254Verifier;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive tests for RapidsnarkProver.
 *
 * <p>Covers: proof generation, proof structure validation, round-trip verification,
 * error handling, multiple proofs, path-based API, and cross-verification with
 * existing test vectors.</p>
 */
class RapidsnarkProverTest {

    private static final String TEST_ZKEY_RESOURCE = "/test-circuits/multiplier/multiplier.zkey";
    private static final String TEST_WTNS_RESOURCE = "/test-circuits/multiplier/multiplier_witness.wtns";
    private static final String TEST_VK_RESOURCE = "/test-circuits/multiplier/verification_key.json";

    private static final String CUBIC_ZKEY_RESOURCE = "/test-circuits/cubic/cubic.zkey";
    private static final String CUBIC_WTNS_RESOURCE = "/test-circuits/cubic/cubic_witness.wtns";
    private static final String CUBIC_VK_RESOURCE = "/test-circuits/cubic/verification_key.json";

    private static RapidsnarkProver prover;

    @BeforeAll
    static void setUp() {
        if (isNativeLibraryAvailable()) {
            prover = new RapidsnarkProver();
        }
    }

    @AfterAll
    static void tearDown() {
        if (prover != null) {
            prover.close();
        }
    }

    // ===== Basic proving tests =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_multiplierCircuit_producesValidProof() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);

        ProveResponse response = prover.proveRaw(zkey, wtns);

        assertNotNull(response);
        assertNotNull(response.proofJson());
        assertFalse(response.proofJson().isBlank());
        assertFalse(response.publicSignals().isEmpty());
        assertEquals("groth16", response.protocol());
        assertEquals("bn128", response.curve());
        assertTrue(response.provingTimeMs() >= 0);

        System.out.println("Proof generated in " + response.provingTimeMs() + " ms");
        System.out.println("Public signals: " + response.publicSignals());
    }

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_multiplierCircuit_correctPublicSignals() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);

        ProveResponse response = prover.proveRaw(zkey, wtns);

        // multiplier circuit: a=3, b=11 → output=33, a=3
        assertEquals(2, response.publicSignals().size(),
                "Expected 2 public signals (output + public input)");
        assertEquals(BigInteger.valueOf(33), response.publicSignals().get(0),
                "First public signal should be product 33");
        assertEquals(BigInteger.valueOf(3), response.publicSignals().get(1),
                "Second public signal should be public input 3");
    }

    // ===== Proof structure validation =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_proofJsonIsValidSnarkjsFormat() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);

        ProveResponse response = prover.proveRaw(zkey, wtns);

        // Parse with the same codec used by verifiers — this validates
        // the proof has pi_a, pi_b, pi_c, protocol, curve fields
        SnarkjsProof parsed = SnarkjsJsonCodec.parseProof(response.proofJson());

        assertNotNull(parsed);
        assertEquals("groth16", parsed.protocol());
        assertEquals("bn128", parsed.curve());
        assertEquals(3, parsed.piA().size(), "pi_a should have 3 coordinates");
        assertEquals(3, parsed.piB().size(), "pi_b should have 3 coordinate pairs");
        assertEquals(3, parsed.piC().size(), "pi_c should have 3 coordinates");

        // G1 points: last coordinate should be 1 (projective affine)
        assertEquals(BigInteger.ONE, parsed.piA().get(2));
        assertEquals(BigInteger.ONE, parsed.piC().get(2));
    }

    // ===== Envelope wrapping =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRawAndWrap_producesValidEnvelope() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);
        String vkJson = new String(loadTestResource(TEST_VK_RESOURCE));

        ZkProofEnvelope envelope = prover.proveRawAndWrap(zkey, wtns, vkJson, "multiplier");

        assertNotNull(envelope);
        assertEquals(ProofSystemId.GROTH16, envelope.proofSystem());
        assertEquals(CurveId.BN254, envelope.curve());
        assertEquals("multiplier", envelope.circuitId().value());
        assertNotNull(envelope.proofBytes());
        assertTrue(envelope.proofBytes().length > 0);
        assertEquals(2, envelope.publicInputs().size());
        assertEquals(BigInteger.valueOf(33), envelope.publicInputs().get(0));
        assertEquals(BigInteger.valueOf(3), envelope.publicInputs().get(1));
    }

    // ===== Round-trip: prove → verify =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveAndVerify_roundTrip_proofIsValid() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);
        String vkJson = new String(loadTestResource(TEST_VK_RESOURCE), StandardCharsets.UTF_8);

        // Prove with rapidsnark
        ZkProofEnvelope envelope = prover.proveRawAndWrap(zkey, wtns, vkJson, "multiplier");

        // Verify with ZeroJ BN254 verifier
        var verifier = new Groth16BN254Verifier();
        VerificationMaterial material = VerificationMaterial.of(
                vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16,
                CurveId.BN254,
                new CircuitId("multiplier"));

        VerificationResult result = verifier.verify(envelope, material);

        assertTrue(result.proofValid(), "Proof should be cryptographically valid. Reason: " + result.reasonCode());

        System.out.println("Round-trip: rapidsnark prove → ZeroJ verify → VALID");
    }

    // ===== Cross-verification with existing test vectors =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proofVerifiesWithSameVerifierAsExistingTestVectors() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);
        String vkJson = new String(loadTestResource(TEST_VK_RESOURCE), StandardCharsets.UTF_8);

        // Generate proof with rapidsnark
        ZkProofEnvelope envelope = prover.proveRawAndWrap(zkey, wtns, vkJson, "multiplier");

        // Use the same verifier class that validates existing test vectors
        // in Groth16BN254VerifierTest.verifyValidMultiplierProof()
        var verifier = new Groth16BN254Verifier();
        VerificationMaterial material = VerificationMaterial.of(
                vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16,
                CurveId.BN254,
                new CircuitId("multiplier"));

        VerificationResult result = verifier.verify(envelope, material);
        assertTrue(result.proofValid(),
                "Rapidsnark proof must verify with same verifier used for snarkjs test vectors");

        // Verify public signals match the existing test vector format
        // The existing groth16-bn254/public.json is ["33", "3"]
        assertEquals(BigInteger.valueOf(33), envelope.publicInputs().get(0));
        assertEquals(BigInteger.valueOf(3), envelope.publicInputs().get(1));
    }

    // ===== Multiple proofs (no state leakage) =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_multipleSequentialProofs_allValid() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);
        String vkJson = new String(loadTestResource(TEST_VK_RESOURCE), StandardCharsets.UTF_8);

        var verifier = new Groth16BN254Verifier();
        VerificationMaterial material = VerificationMaterial.of(
                vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16,
                CurveId.BN254,
                new CircuitId("multiplier"));

        for (int i = 0; i < 5; i++) {
            ZkProofEnvelope envelope = prover.proveRawAndWrap(zkey, wtns, vkJson, "multiplier");
            VerificationResult result = verifier.verify(envelope, material);
            assertTrue(result.proofValid(), "Proof #" + (i + 1) + " should be valid");
        }
    }

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_eachProofIsDifferent() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(TEST_WTNS_RESOURCE);

        ProveResponse proof1 = prover.proveRaw(zkey, wtns);
        ProveResponse proof2 = prover.proveRaw(zkey, wtns);

        // Groth16 uses randomization — same inputs should produce different proofs
        assertNotEquals(proof1.proofJson(), proof2.proofJson(),
                "Two proofs from same inputs should differ (Groth16 randomization)");

        // But public signals must be identical
        assertEquals(proof1.publicSignals(), proof2.publicSignals(),
                "Public signals should be identical for same inputs");
    }

    // ===== Multi-circuit: cubic =====

    @Test
    @EnabledIf("isCubicFixturesAvailable")
    void proveRaw_cubicCircuit_correctPublicSignals() throws Exception {
        byte[] zkey = loadTestResource(CUBIC_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(CUBIC_WTNS_RESOURCE);

        ProveResponse response = prover.proveRaw(zkey, wtns);

        // cubic circuit: x=3 → y=x³=27
        assertEquals(1, response.publicSignals().size(), "Cubic has 1 public signal (output y)");
        assertEquals(BigInteger.valueOf(27), response.publicSignals().get(0),
                "Public signal should be 3³ = 27");
        assertEquals("groth16", response.protocol());
        assertEquals("bn128", response.curve());
    }

    @Test
    @EnabledIf("isCubicFixturesAvailable")
    void proveAndVerify_cubicCircuit_roundTrip() throws Exception {
        byte[] zkey = loadTestResource(CUBIC_ZKEY_RESOURCE);
        byte[] wtns = loadTestResource(CUBIC_WTNS_RESOURCE);
        String vkJson = new String(loadTestResource(CUBIC_VK_RESOURCE), StandardCharsets.UTF_8);

        ZkProofEnvelope envelope = prover.proveRawAndWrap(zkey, wtns, vkJson, "cubic");

        var verifier = new Groth16BN254Verifier();
        VerificationMaterial material = VerificationMaterial.of(
                vkJson.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BN254, new CircuitId("cubic"));

        VerificationResult result = verifier.verify(envelope, material);
        assertTrue(result.proofValid(), "Cubic proof should verify. Reason: " + result.reasonCode());
    }

    @Test
    @EnabledIf("isBothFixturesAvailable")
    void proveRaw_differentCircuits_differentProofStructure() throws Exception {
        // Prove both circuits with the same prover instance
        ProveResponse multiplier = prover.proveRaw(
                loadTestResource(TEST_ZKEY_RESOURCE), loadTestResource(TEST_WTNS_RESOURCE));
        ProveResponse cubic = prover.proveRaw(
                loadTestResource(CUBIC_ZKEY_RESOURCE), loadTestResource(CUBIC_WTNS_RESOURCE));

        // Different circuits → different number of public signals
        assertEquals(2, multiplier.publicSignals().size(), "Multiplier: 2 public signals");
        assertEquals(1, cubic.publicSignals().size(), "Cubic: 1 public signal");

        // Both are groth16/bn128
        assertEquals(multiplier.protocol(), cubic.protocol());
        assertEquals(multiplier.curve(), cubic.curve());
    }

    // ===== Path-based API =====

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_withFilePaths_producesValidProof(@TempDir Path tempDir) throws Exception {
        // Write test resources to temp files
        Path zkeyFile = tempDir.resolve("multiplier.zkey");
        Path wtnsFile = tempDir.resolve("multiplier.wtns");
        Files.write(zkeyFile, loadTestResource(TEST_ZKEY_RESOURCE));
        Files.write(wtnsFile, loadTestResource(TEST_WTNS_RESOURCE));

        ProveResponse response = prover.proveRaw(zkeyFile, wtnsFile);

        assertNotNull(response);
        assertEquals("groth16", response.protocol());
        assertEquals("bn128", response.curve());
        assertEquals(2, response.publicSignals().size());
        assertEquals(BigInteger.valueOf(33), response.publicSignals().get(0));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveRaw_nonexistentPath_throwsProverException() {
        assertThrows(ProverException.class, () ->
                prover.proveRaw(Path.of("/nonexistent/circuit.zkey"), Path.of("/nonexistent/witness.wtns")));
    }

    // ===== Error handling =====

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveRaw_nullZkey_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () ->
                prover.proveRaw(null, new byte[]{1}));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveRaw_nullWtns_throwsIllegalArgument() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        assertThrows(IllegalArgumentException.class, () ->
                prover.proveRaw(zkey, null));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveRaw_emptyZkey_throwsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () ->
                prover.proveRaw(new byte[0], new byte[]{1}));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveRaw_emptyWtns_throwsIllegalArgument() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        assertThrows(IllegalArgumentException.class, () ->
                prover.proveRaw(zkey, new byte[0]));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveRaw_garbageZkey_throwsProverException() {
        byte[] garbageZkey = "not a valid zkey file".getBytes();
        byte[] garbageWtns = "not a valid wtns file".getBytes();

        assertThrows(ProverException.class, () ->
                prover.proveRaw(garbageZkey, garbageWtns));
    }

    @Test
    @EnabledIf("isNativeLibraryAndTestFixturesAvailable")
    void proveRaw_validZkeyGarbageWtns_throwsProverException() throws Exception {
        byte[] zkey = loadTestResource(TEST_ZKEY_RESOURCE);
        byte[] garbageWtns = "not a valid wtns file".getBytes();

        assertThrows(ProverException.class, () ->
                prover.proveRaw(zkey, garbageWtns));
    }

    // ===== ProverService interface tests =====

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void prove_throwsUnsupportedOperation() {
        assertThrows(UnsupportedOperationException.class,
                () -> prover.prove(null));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void proveAndWrap_throwsUnsupportedOperation() {
        assertThrows(UnsupportedOperationException.class,
                () -> prover.proveAndWrap(null, "circuit"));
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void isHealthy_returnsTrue() {
        assertTrue(prover.isHealthy());
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void listCircuits_returnsEmptyList() {
        assertTrue(prover.listCircuits().isEmpty());
    }

    // ===== Helper methods =====

    static boolean isNativeLibraryAvailable() {
        return NativeLibraryLoader.isAvailable();
    }

    static boolean isNativeLibraryAndTestFixturesAvailable() {
        return isNativeLibraryAvailable()
                && RapidsnarkProverTest.class.getResource(TEST_ZKEY_RESOURCE) != null
                && RapidsnarkProverTest.class.getResource(TEST_WTNS_RESOURCE) != null;
    }

    static boolean isCubicFixturesAvailable() {
        return isNativeLibraryAvailable()
                && RapidsnarkProverTest.class.getResource(CUBIC_ZKEY_RESOURCE) != null
                && RapidsnarkProverTest.class.getResource(CUBIC_WTNS_RESOURCE) != null;
    }

    static boolean isBothFixturesAvailable() {
        return isNativeLibraryAndTestFixturesAvailable() && isCubicFixturesAvailable();
    }

    private static byte[] loadTestResource(String resourcePath) throws IOException {
        try (InputStream in = RapidsnarkProverTest.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new IOException("Test resource not found: " + resourcePath);
            }
            return in.readAllBytes();
        }
    }
}
