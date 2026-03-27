package com.bloxbean.cardano.zeroj.ingestion;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Groth16BN254Verifier;
import com.bloxbean.cardano.zeroj.submission.AppProofSubmission;
import com.bloxbean.cardano.zeroj.submission.Ed25519Signer;
import com.bloxbean.cardano.zeroj.submission.SubmissionHash;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.RejectionReason;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult.ValidationStage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Security-focused tests for the submission ingestion pipeline.
 *
 * <p>Uses real snarkjs Groth16/BN254 proofs and Ed25519 signatures.
 * Tests every rejection path explicitly.</p>
 */
class SubmissionIngestionPipelineTest {

    private static final String APP_ID = "test-app";
    private static final String CIRCUIT_ID = "multiplier";
    private static final String CIRCUIT_VERSION = "v1";
    private static final String SUBMITTER_ID = "alice";

    private SubmissionIngestionPipeline pipeline;
    private InMemoryVerificationKeyRegistry vkRegistry;
    private InMemorySubmitterRegistry submitterRegistry;
    private InMemoryCircuitAllowlist circuitAllowlist;
    private InMemoryStateRootStore stateRootStore;
    private InMemorySequenceTracker sequenceTracker;
    private InMemoryNullifierStore nullifierStore;

    private KeyPair aliceKeyPair;
    private KeyPair bobKeyPair;
    private byte[] vkHash;
    private String proofJson;
    private byte[] genesisRoot;

    @BeforeEach
    void setUp() {
        // Generate Ed25519 key pairs
        aliceKeyPair = Ed25519Signer.generateKeyPair();
        bobKeyPair = Ed25519Signer.generateKeyPair();

        // Load real snarkjs test vectors
        proofJson = loadString("/test-vectors/groth16-bn254/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bn254/verification_key.json");
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        vkHash = sha256(vkBytes);

        // Set up verifier with real BN254 Groth16 backend
        var verifierRegistry = VerifierRegistry.empty();
        verifierRegistry.register(new Groth16BN254Verifier());

        // VK registry
        vkRegistry = new InMemoryVerificationKeyRegistry();
        vkRegistry.register(VerificationMaterial.of(
                vkBytes, ProofSystemId.GROTH16, CurveId.BN254,
                new CircuitId(CIRCUIT_ID), vkHash));

        var orchestrator = new VerifierOrchestrator(verifierRegistry, vkRegistry);

        // Submitter registry — Alice authorized, Bob not registered
        submitterRegistry = new InMemorySubmitterRegistry();
        submitterRegistry.register(SUBMITTER_ID, aliceKeyPair.getPublic(), APP_ID);

        // Circuit allowlist
        circuitAllowlist = new InMemoryCircuitAllowlist();
        circuitAllowlist.allow(CIRCUIT_ID, CIRCUIT_VERSION);

        // State root store — initialize with genesis root
        stateRootStore = new InMemoryStateRootStore();
        genesisRoot = sha256("genesis".getBytes(StandardCharsets.UTF_8));
        stateRootStore.initialize(APP_ID, genesisRoot);

        // Sequence tracker + nullifier store
        sequenceTracker = new InMemorySequenceTracker();
        nullifierStore = new InMemoryNullifierStore();

        pipeline = new SubmissionIngestionPipeline(
                orchestrator, vkRegistry, submitterRegistry, circuitAllowlist,
                stateRootStore, sequenceTracker, nullifierStore);
    }

    // ==================== HAPPY PATH ====================

    @Test
    void happyPath_validSubmissionAccepted() {
        var submission = validSubmission(1, genesisRoot, sha256("state-1".getBytes()));
        var result = pipeline.process(submission);

        assertTrue(result.accepted(), "Valid submission should be accepted. Got: " + result);
        assertEquals(ValidationStage.ACCEPTED, result.stage());
    }

    @Test
    void happyPath_sequentialSubmissionsAccepted() {
        var root1 = sha256("state-1".getBytes());
        var root2 = sha256("state-2".getBytes());

        var sub1 = validSubmission(1, genesisRoot, root1);
        var sub2 = validSubmission(2, root1, root2);

        assertTrue(pipeline.process(sub1).accepted());
        assertTrue(pipeline.process(sub2).accepted());
    }

    // ==================== STAGE 2: SIGNATURE ATTACKS ====================

    @Test
    void security_unknownSubmitterRejected() {
        var submission = buildSubmission("unknown-attacker", bobKeyPair, 1, genesisRoot, sha256("hack".getBytes()), null);
        var result = pipeline.process(submission);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.SIGNATURE, result.stage());
        assertEquals(RejectionReason.UNKNOWN_SUBMITTER, result.reason().orElse(null));
    }

    @Test
    void security_unauthorizedSubmitterRejected() {
        // Register bob but don't authorize for this app
        submitterRegistry.register("bob", bobKeyPair.getPublic(), "other-app");

        var submission = buildSubmission("bob", bobKeyPair, 1, genesisRoot, sha256("hack".getBytes()), null);
        var result = pipeline.process(submission);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.SIGNATURE, result.stage());
        assertEquals(RejectionReason.UNAUTHORIZED_SUBMITTER, result.reason().orElse(null));
    }

    @Test
    void security_tamperedSignatureRejected() {
        var submission = validSubmissionUnsigned(1, genesisRoot, sha256("state-1".getBytes()));
        // Sign with wrong key (bob's key, but submitterId is alice)
        byte[] hash = SubmissionHash.compute(submission);
        byte[] wrongSig = Ed25519Signer.sign(hash, bobKeyPair.getPrivate());

        var tampered = AppProofSubmission.builder()
                .appId(submission.appId())
                .proofSystem(submission.proofSystem())
                .curve(submission.curve())
                .circuitId(submission.circuitId())
                .circuitVersion(submission.circuitVersion())
                .prevStateRoot(submission.prevStateRoot())
                .newStateRoot(submission.newStateRoot())
                .publicInputs(submission.publicInputs())
                .proofBytes(submission.proofBytes())
                .vkHash(submission.vkHash())
                .submitterId(submission.submitterId())
                .submitterSignature(wrongSig) // signed by bob, not alice
                .sequence(submission.sequence())
                .build();

        var result = pipeline.process(tampered);
        assertFalse(result.accepted());
        assertEquals(ValidationStage.SIGNATURE, result.stage());
        assertEquals(RejectionReason.INVALID_SIGNATURE, result.reason().orElse(null));
    }

    @Test
    void security_signatureOverDifferentDataRejected() {
        // Build a valid submission but replace the signature with one over different data
        var submission = validSubmissionUnsigned(1, genesisRoot, sha256("state-1".getBytes()));
        byte[] forgedMessage = sha256("forged-data".getBytes());
        byte[] forgedSig = Ed25519Signer.sign(forgedMessage, aliceKeyPair.getPrivate());

        var forged = rebuildWithSignature(submission, forgedSig);
        var result = pipeline.process(forged);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.SIGNATURE, result.stage());
        assertEquals(RejectionReason.INVALID_SIGNATURE, result.reason().orElse(null));
    }

    // ==================== STAGE 3: CIRCUIT ATTACKS ====================

    @Test
    void security_retiredCircuitRejected() {
        circuitAllowlist.retire(CIRCUIT_ID, CIRCUIT_VERSION);

        var submission = validSubmission(1, genesisRoot, sha256("state-1".getBytes()));
        var result = pipeline.process(submission);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.CIRCUIT_RESOLUTION, result.stage());
        assertEquals(RejectionReason.RETIRED_CIRCUIT, result.reason().orElse(null));
    }

    @Test
    void security_unknownCircuitVersionRejected() {
        var submission = buildSubmission(SUBMITTER_ID, aliceKeyPair, 1, genesisRoot,
                sha256("state-1".getBytes()), null, "v99");
        var result = pipeline.process(submission);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.CIRCUIT_RESOLUTION, result.stage());
    }

    // ==================== STAGE 4: CRYPTOGRAPHIC ATTACKS ====================

    @Test
    void security_invalidProofRejected() {
        // Use tampered proof (pi_a.x + 1)
        String tamperedProofJson = loadString("/test-vectors/groth16-bn254-invalid/proof_tampered.json");

        var submission = buildSubmissionWithProof(tamperedProofJson, 1, genesisRoot, sha256("state-1".getBytes()));
        var result = pipeline.process(submission);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.CRYPTOGRAPHIC_VERIFICATION, result.stage());
        assertEquals(RejectionReason.PROOF_INVALID, result.reason().orElse(null));
    }

    // ==================== STAGE 5: POLICY ATTACKS ====================

    @Test
    void security_staleStateRootRejected() {
        // Submit with a root that doesn't match the current state
        byte[] wrongRoot = sha256("wrong-root".getBytes());
        var submission = validSubmission(1, wrongRoot, sha256("state-1".getBytes()));

        var result = pipeline.process(submission);
        assertFalse(result.accepted());
        assertEquals(ValidationStage.POLICY, result.stage());
        assertEquals(RejectionReason.STALE_STATE_ROOT, result.reason().orElse(null));
    }

    @Test
    void security_replayedSequenceRejected() {
        var root1 = sha256("state-1".getBytes());
        var sub1 = validSubmission(1, genesisRoot, root1);
        assertTrue(pipeline.process(sub1).accepted());

        // Replay with same sequence number
        var replay = validSubmission(1, root1, sha256("state-2".getBytes()));
        var result = pipeline.process(replay);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.POLICY, result.stage());
        assertEquals(RejectionReason.DUPLICATE_SEQUENCE, result.reason().orElse(null));
    }

    @Test
    void security_usedNullifierRejected() {
        byte[] nullifier = sha256("unique-nullifier".getBytes());

        var root1 = sha256("state-1".getBytes());
        var sub1 = buildSubmission(SUBMITTER_ID, aliceKeyPair, 1, genesisRoot, root1, nullifier);
        assertTrue(pipeline.process(sub1).accepted());

        // Try to reuse the same nullifier (double-spend attempt)
        var root2 = sha256("state-2".getBytes());
        var sub2 = buildSubmission(SUBMITTER_ID, aliceKeyPair, 2, root1, root2, nullifier);
        var result = pipeline.process(sub2);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.POLICY, result.stage());
        assertEquals(RejectionReason.USED_NULLIFIER, result.reason().orElse(null));
    }

    @Test
    void security_outOfOrderSequenceRejected() {
        // Accept sequence 5
        var root1 = sha256("state-1".getBytes());
        var sub1 = validSubmission(5, genesisRoot, root1);
        assertTrue(pipeline.process(sub1).accepted());

        // Try sequence 3 (going backwards)
        var root2 = sha256("state-2".getBytes());
        var sub2 = validSubmission(3, root1, root2);
        var result = pipeline.process(sub2);

        assertFalse(result.accepted());
        assertEquals(ValidationStage.POLICY, result.stage());
        assertEquals(RejectionReason.DUPLICATE_SEQUENCE, result.reason().orElse(null));
    }

    // ==================== HELPERS ====================

    private AppProofSubmission validSubmission(long sequence, byte[] prevRoot, byte[] newRoot) {
        return buildSubmission(SUBMITTER_ID, aliceKeyPair, sequence, prevRoot, newRoot, null);
    }

    private AppProofSubmission validSubmissionUnsigned(long sequence, byte[] prevRoot, byte[] newRoot) {
        return AppProofSubmission.builder()
                .appId(APP_ID)
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(CIRCUIT_ID)
                .circuitVersion(CIRCUIT_VERSION)
                .prevStateRoot(prevRoot)
                .newStateRoot(newRoot)
                .publicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .vkHash(vkHash)
                .submitterId(SUBMITTER_ID)
                .submitterSignature(new byte[64]) // placeholder
                .sequence(sequence)
                .build();
    }

    private AppProofSubmission buildSubmission(String submitterId, KeyPair keyPair,
                                                long sequence, byte[] prevRoot, byte[] newRoot,
                                                byte[] nullifier) {
        return buildSubmission(submitterId, keyPair, sequence, prevRoot, newRoot, nullifier, CIRCUIT_VERSION);
    }

    private AppProofSubmission buildSubmission(String submitterId, KeyPair keyPair,
                                                long sequence, byte[] prevRoot, byte[] newRoot,
                                                byte[] nullifier, String circuitVersion) {
        // Build unsigned first to compute hash
        var unsigned = AppProofSubmission.builder()
                .appId(APP_ID)
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(CIRCUIT_ID)
                .circuitVersion(circuitVersion)
                .prevStateRoot(prevRoot)
                .newStateRoot(newRoot)
                .publicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .vkHash(vkHash)
                .submitterId(submitterId)
                .submitterSignature(new byte[64]) // placeholder for hash computation
                .sequence(sequence)
                .nullifier(nullifier)
                .build();

        // Sign the submission hash
        byte[] hash = SubmissionHash.compute(unsigned);
        byte[] signature = Ed25519Signer.sign(hash, keyPair.getPrivate());

        // Rebuild with real signature
        return rebuildWithSignature(unsigned, signature);
    }

    private AppProofSubmission buildSubmissionWithProof(String customProofJson,
                                                         long sequence, byte[] prevRoot, byte[] newRoot) {
        var unsigned = AppProofSubmission.builder()
                .appId(APP_ID)
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(CIRCUIT_ID)
                .circuitVersion(CIRCUIT_VERSION)
                .prevStateRoot(prevRoot)
                .newStateRoot(newRoot)
                .publicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(customProofJson.getBytes(StandardCharsets.UTF_8))
                .vkHash(vkHash)
                .submitterId(SUBMITTER_ID)
                .submitterSignature(new byte[64])
                .sequence(sequence)
                .build();

        byte[] hash = SubmissionHash.compute(unsigned);
        byte[] signature = Ed25519Signer.sign(hash, aliceKeyPair.getPrivate());
        return rebuildWithSignature(unsigned, signature);
    }

    private AppProofSubmission rebuildWithSignature(AppProofSubmission original, byte[] signature) {
        return AppProofSubmission.builder()
                .appId(original.appId())
                .proofSystem(original.proofSystem())
                .curve(original.curve())
                .circuitId(original.circuitId())
                .circuitVersion(original.circuitVersion())
                .prevStateRoot(original.prevStateRoot())
                .newStateRoot(original.newStateRoot())
                .publicInputs(original.publicInputs())
                .proofBytes(original.proofBytes())
                .vkHash(original.vkHash())
                .submitterId(original.submitterId())
                .submitterSignature(signature)
                .sequence(original.sequence())
                .nullifier(original.nullifier())
                .metadata(original.metadata())
                .build();
    }

    private String loadString(String path) {
        try (var in = getClass().getResourceAsStream(path)) {
            if (in == null) fail("Resource not found: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return fail("Failed to read: " + path);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
