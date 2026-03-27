package com.bloxbean.cardano.zeroj.patterns;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.patterns.membership.MembershipInput;
import com.bloxbean.cardano.zeroj.patterns.membership.MembershipVerifier;
import com.bloxbean.cardano.zeroj.patterns.nullifier.ClaimResult;
import com.bloxbean.cardano.zeroj.patterns.nullifier.NullifierClaimInput;
import com.bloxbean.cardano.zeroj.patterns.nullifier.NullifierClaimVerifier;
import com.bloxbean.cardano.zeroj.patterns.statetransition.StateTransitionInput;
import com.bloxbean.cardano.zeroj.patterns.statetransition.StateTransitionVerifier;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Groth16BN254Verifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Sample flows demonstrating the complete lifecycle for each pattern using
 * the high-level input/output/policy APIs.
 * <p>
 * Each flow shows: domain data → input object → attach proof → verify → enriched result.
 * Uses real snarkjs Groth16/BN254 proofs (multiplier circuit repurposed conceptually).
 */
class PatternFlowTest {

    private VerifierOrchestrator orchestrator;
    private VerificationMaterial material;
    private byte[] proofBytes;

    @BeforeEach
    void setUp() {
        String proofJson = loadString("/test-vectors/groth16-bn254/proof.json");
        String vkJson = loadString("/test-vectors/groth16-bn254/verification_key.json");
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);

        var registry = VerifierRegistry.empty();
        registry.register(new Groth16BN254Verifier());

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BN254,
                new CircuitId("multiplier"));
        vkRegistry.register(material);

        orchestrator = new VerifierOrchestrator(registry, vkRegistry);
        proofBytes = proofJson.getBytes(StandardCharsets.UTF_8);
    }

    // ==================== State Transition Flow ====================

    @Test
    void stateTransition_completeFlow() {
        // 1. DOMAIN: prepare input from raw state data
        var input = StateTransitionInput.fromRawStates(
                "old-account-balance:1000".getBytes(StandardCharsets.UTF_8),
                "new-account-balance:700".getBytes(StandardCharsets.UTF_8),
                List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)));

        // state hashes are 32-byte SHA-256
        assertEquals(32, input.oldStateHash().length);
        assertEquals(32, input.newStateHash().length);

        // 2. PROOF: attach externally generated proof (snarkjs, sidecar, etc.)
        var transition = input.withProof(proofBytes, "multiplier");
        assertEquals(ProofSystemId.GROTH16, transition.proofSystem());
        assertEquals(CurveId.BN254, transition.curve());

        // 3. VERIFY: get enriched result with anchoring metadata
        var verifier = new StateTransitionVerifier(orchestrator);
        var result = verifier.verifyTransition(transition, material);

        assertTrue(result.accepted(), "Transition should be verified");
        assertTrue(result.proofValid());
        assertNotNull(result.transitionHash(), "Should have anchoring hash");
        assertEquals(32, result.transitionHash().length);
        assertArrayEquals(input.oldStateHash(), result.oldStateHash());
        assertArrayEquals(input.newStateHash(), result.newStateHash());
    }

    @Test
    void stateTransition_inputFromPrecomputedHashes() {
        // Alternative: input from pre-computed hashes (when hashes are known)
        var input = StateTransitionInput.of(
                sha256("state-v1"), sha256("state-v2"),
                List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)));

        var transition = input.withProof(proofBytes, "multiplier");
        var result = new StateTransitionVerifier(orchestrator).verifyTransition(transition, material);
        assertTrue(result.accepted());
    }

    // ==================== Nullifier Claim Flow ====================

    @Test
    void nullifierClaim_completeFlow() {
        // 1. DOMAIN: prepare claim input
        var input = new NullifierClaimInput(
                sha256("unique-secret"),     // nullifier
                sha256("eligible-set"),      // commitment
                BigInteger.valueOf(33),      // claim value
                List.of(BigInteger.valueOf(3)));  // additional public inputs

        // 2. PROOF: attach proof
        var claim = input.withProof(proofBytes, "multiplier");

        // 3. VERIFY: get enriched result
        var verifier = new NullifierClaimVerifier(orchestrator);
        ClaimResult result = verifier.verifyAndAcceptClaim(claim, material);

        assertTrue(result.accepted(), "First claim should be accepted");
        assertFalse(result.nullifierAlreadySpent());
        assertTrue(result.proofValid());

        // 4. DOUBLE-CLAIM: same nullifier rejected
        ClaimResult doubleResult = verifier.verifyAndAcceptClaim(claim, material);
        assertFalse(doubleResult.accepted());
        assertTrue(doubleResult.nullifierAlreadySpent(), "Double-claim should be detected");
    }

    @Test
    void nullifierClaim_differentNullifiersAccepted() {
        var verifier = new NullifierClaimVerifier(orchestrator);

        var claim1 = new NullifierClaimInput(sha256("secret-1"), sha256("set"),
                BigInteger.valueOf(33), List.of(BigInteger.valueOf(3)))
                .withProof(proofBytes, "multiplier");
        var claim2 = new NullifierClaimInput(sha256("secret-2"), sha256("set"),
                BigInteger.valueOf(33), List.of(BigInteger.valueOf(3)))
                .withProof(proofBytes, "multiplier");

        assertTrue(verifier.verifyAndAcceptClaim(claim1, material).accepted());
        assertTrue(verifier.verifyAndAcceptClaim(claim2, material).accepted());
    }

    // ==================== Membership Proof Flow ====================

    @Test
    void membership_completeFlow() {
        byte[] merkleRoot = sha256("merkle-root");

        // 1. DOMAIN: prepare membership input
        var input = MembershipInput.of(merkleRoot,
                List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)));

        // 2. PROOF: attach proof
        var proof = input.withProof(proofBytes, "multiplier");

        // 3. VERIFY: get enriched result with root match status
        var verifier = new MembershipVerifier(orchestrator);
        var result = verifier.verifyMembership(proof, merkleRoot, material);

        assertTrue(result.accepted(), "Membership should be verified");
        assertTrue(result.rootMatched());
        assertTrue(result.proofValid());
    }

    @Test
    void membership_wrongRoot_detected() {
        var input = MembershipInput.of(sha256("root-A"),
                List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)));
        var proof = input.withProof(proofBytes, "multiplier");

        var verifier = new MembershipVerifier(orchestrator);
        var result = verifier.verifyMembership(proof, sha256("root-B"), material);

        assertFalse(result.accepted());
        assertFalse(result.rootMatched(), "Root mismatch should be detected");
    }

    // ==================== Policy Template Flow ====================

    @Test
    void patternPolicy_stateTransitionPolicy() {
        var policy = PatternPolicies.stateTransition(orchestrator);
        var envelope = buildEnvelope();

        var result = policy.evaluate(envelope, material);
        assertTrue(result.accepted(), "Should pass standard state transition policy");
    }

    @Test
    void patternPolicy_wrongCurveRejected() {
        // BLS12-381 policy rejects a BN254 proof
        var policy = PatternPolicies.groth16Bls12381(orchestrator, 2);
        var envelope = buildEnvelope(); // BN254

        var result = policy.evaluate(envelope, material);
        assertFalse(result.accepted(), "BLS12-381 policy should reject BN254 proof");
    }

    @Test
    void patternPolicy_tooFewInputsRejected() {
        var policy = PatternPolicies.groth16Bn254(orchestrator, 10);
        var envelope = buildEnvelope(); // 2 inputs

        var result = policy.evaluate(envelope, material);
        assertFalse(result.accepted(), "Should reject: need 10 inputs, have 2");
    }

    // ==================== Helpers ====================

    private ZkProofEnvelope buildEnvelope() {
        return SnarkjsJsonCodec.toEnvelopeFromJson(
                new String(proofBytes, StandardCharsets.UTF_8),
                loadString("/test-vectors/groth16-bn254/verification_key.json"),
                loadString("/test-vectors/groth16-bn254/public.json"),
                new CircuitId("multiplier"));
    }

    private String loadString(String path) {
        try (var in = getClass().getResourceAsStream(path)) {
            if (in == null) fail("Resource not found: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) { return fail("Failed to read: " + path); }
    }

    private static byte[] sha256(String data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data.getBytes(StandardCharsets.UTF_8)); }
        catch (Exception e) { throw new RuntimeException(e); }
    }
}
