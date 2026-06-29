package com.bloxbean.cardano.zeroj.patterns;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.patterns.membership.MembershipProof;
import com.bloxbean.cardano.zeroj.patterns.membership.MembershipVerifier;
import com.bloxbean.cardano.zeroj.patterns.nullifier.NullifierClaim;
import com.bloxbean.cardano.zeroj.patterns.nullifier.NullifierClaimVerifier;
import com.bloxbean.cardano.zeroj.patterns.statetransition.StateTransition;
import com.bloxbean.cardano.zeroj.patterns.statetransition.StateTransitionVerifier;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for all three ZK patterns using real snarkjs Groth16/BLS12-381 proofs.
 *
 * <p>The multiplier circuit (a * b = c, public inputs: [c, a]) is repurposed to
 * demonstrate each pattern conceptually — in production, each pattern would have
 * its own purpose-built circuit.</p>
 */
class PatternsIntegrationTest {

    private VerifierOrchestrator orchestrator;
    private VerificationMaterial material;
    private String proofJson;
    private String vkJson;

    @BeforeEach
    void setUp() {
        proofJson = loadString("/test-vectors/groth16-bls12381/proof.json");
        vkJson = loadString("/test-vectors/groth16-bls12381/verification_key.json");
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);

        var registry = VerifierRegistry.empty();
        registry.register(new Groth16BLS12381PureJavaVerifier());

        var vkRegistry = new InMemoryVerificationKeyRegistry();
        material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BLS12_381,
                new CircuitId("multiplier"));
        vkRegistry.register(material);

        orchestrator = new VerifierOrchestrator(registry, vkRegistry);
    }

    // ==================== Pattern 1: State Transition ====================

    @Test
    void stateTransition_validTransitionVerified() {
        var transition = StateTransition.builder()
                .oldStateHash(sha256("old-state"))
                .newStateHash(sha256("new-state"))
                .additionalPublicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId("multiplier")
                .build();

        var verifier = new StateTransitionVerifier(orchestrator, null);
        var result = verifier.verify(transition, material);
        assertTrue(result.proofValid(), "State transition should verify: " + result);
    }

    @Test
    void stateTransition_hashIsDeterministic() {
        var t1 = StateTransition.builder()
                .oldStateHash(sha256("s1"))
                .newStateHash(sha256("s2"))
                .proofBytes(new byte[]{1})
                .circuitId("test")
                .build();
        var t2 = StateTransition.builder()
                .oldStateHash(sha256("s1"))
                .newStateHash(sha256("s2"))
                .proofBytes(new byte[]{1})
                .circuitId("test")
                .build();

        assertArrayEquals(t1.transitionHash(), t2.transitionHash());
    }

    @Test
    void stateTransition_differentStatesProduceDifferentHash() {
        var t1 = StateTransition.builder()
                .oldStateHash(sha256("s1")).newStateHash(sha256("s2"))
                .proofBytes(new byte[]{1}).circuitId("test").build();
        var t2 = StateTransition.builder()
                .oldStateHash(sha256("s1")).newStateHash(sha256("s3"))
                .proofBytes(new byte[]{1}).circuitId("test").build();

        assertFalse(java.util.Arrays.equals(t1.transitionHash(), t2.transitionHash()));
    }

    // ==================== Pattern 2: Nullifier Claim ====================

    @Test
    void nullifierClaim_validClaimAccepted() {
        var claim = NullifierClaim.builder()
                .nullifier(sha256("unique-secret"))
                .commitment(sha256("eligible-set-root"))
                .claimValue(BigInteger.valueOf(33))
                .additionalPublicInputs(List.of(BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();

        var verifier = new NullifierClaimVerifier(orchestrator);
        var result = verifier.verifyAndAccept(claim, material);
        assertTrue(result.accepted(), "Valid claim should be accepted: " + result);
    }

    @Test
    void nullifierClaim_doubleClaimRejected() {
        var verifier = new NullifierClaimVerifier(orchestrator);

        var claim1 = NullifierClaim.builder()
                .nullifier(sha256("same-nullifier"))
                .commitment(sha256("set"))
                .claimValue(BigInteger.valueOf(33))
                .additionalPublicInputs(List.of(BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();

        // First claim succeeds
        assertTrue(verifier.verifyAndAccept(claim1, material).accepted());
        assertTrue(verifier.isNullifierUsed(sha256("same-nullifier")));

        // Second claim with same nullifier fails
        var claim2 = NullifierClaim.builder()
                .nullifier(sha256("same-nullifier"))
                .commitment(sha256("set"))
                .claimValue(BigInteger.valueOf(33))
                .additionalPublicInputs(List.of(BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();

        var result = verifier.verifyAndAccept(claim2, material);
        assertFalse(result.accepted());
        assertEquals(VerificationResult.ReasonCode.USED_NULLIFIER, result.reasonCode().orElse(null));
    }

    @Test
    void nullifierClaim_differentNullifiersAllowed() {
        var verifier = new NullifierClaimVerifier(orchestrator);

        var claim1 = NullifierClaim.builder()
                .nullifier(sha256("nullifier-1"))
                .commitment(sha256("set"))
                .claimValue(BigInteger.valueOf(33))
                .additionalPublicInputs(List.of(BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();
        var claim2 = NullifierClaim.builder()
                .nullifier(sha256("nullifier-2"))
                .commitment(sha256("set"))
                .claimValue(BigInteger.valueOf(33))
                .additionalPublicInputs(List.of(BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();

        assertTrue(verifier.verifyAndAccept(claim1, material).accepted());
        assertTrue(verifier.verifyAndAccept(claim2, material).accepted());
    }

    // ==================== Pattern 3: Membership Proof ====================

    @Test
    void membership_validProofWithMatchingRoot() {
        byte[] root = sha256("merkle-root");

        var proof = MembershipProof.builder()
                .merkleRoot(root)
                .constraintOutputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();

        var verifier = new MembershipVerifier(orchestrator);
        var result = verifier.verify(proof, root, material);
        assertTrue(result.proofValid(), "Membership proof should verify: " + result);
    }

    @Test
    void membership_wrongRootRejected() {
        var proof = MembershipProof.builder()
                .merkleRoot(sha256("root-A"))
                .constraintOutputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .circuitId("multiplier")
                .build();

        byte[] expectedRoot = sha256("root-B");
        var verifier = new MembershipVerifier(orchestrator);
        var result = verifier.verify(proof, expectedRoot, material);
        assertFalse(result.accepted());
        assertEquals(VerificationResult.ReasonCode.STALE_STATE_ROOT, result.reasonCode().orElse(null));
    }

    // ==================== Policy Template ====================

    @Test
    void policyTemplate_validProofPassesAllRules() {
        var policy = VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BLS12_381)
                .requireMinPublicInputs(2)
                .build();

        var envelope = buildEnvelope();
        var result = policy.evaluate(envelope, material);
        assertTrue(result.accepted(), "Should pass all rules: " + result);
    }

    @Test
    void policyTemplate_wrongCurveRejected() {
        var policy = VerificationPolicyTemplate.create(orchestrator)
                .requireCurve(CurveId.BN254) // wrong curve
                .build();

        var envelope = buildEnvelope();
        var result = policy.evaluate(envelope, material);
        assertFalse(result.accepted());
    }

    @Test
    void policyTemplate_tooFewPublicInputsRejected() {
        var policy = VerificationPolicyTemplate.create(orchestrator)
                .requireMinPublicInputs(10) // our proof has 2
                .build();

        var envelope = buildEnvelope();
        var result = policy.evaluate(envelope, material);
        assertFalse(result.accepted());
    }

    @Test
    void policyTemplate_customPreRuleRejects() {
        var policy = VerificationPolicyTemplate.create(orchestrator)
                .addPreRule("must-be-v2", e ->
                        e.circuitId().value().contains("v2") ? null : "Only v2 circuits allowed")
                .build();

        var envelope = buildEnvelope(); // circuitId = "multiplier" (no "v2")
        var result = policy.evaluate(envelope, material);
        assertFalse(result.accepted());
        assertTrue(result.message().orElse("").contains("v2"));
    }

    // ==================== Helpers ====================

    private ZkProofEnvelope buildEnvelope() {
        return SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson,
                loadString("/test-vectors/groth16-bls12381/public.json"),
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
