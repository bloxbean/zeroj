package com.bloxbean.cardano.zeroj.patterns.membership;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;

import java.util.Objects;

/**
 * Verifies a {@link MembershipProof} against a known Merkle root.
 *
 * <p>Combines proof verification with root validation — ensures the proof
 * is for the expected set (identified by its Merkle root).</p>
 */
public class MembershipVerifier {

    private final VerifierOrchestrator orchestrator;

    public MembershipVerifier(VerifierOrchestrator orchestrator) {
        this.orchestrator = Objects.requireNonNull(orchestrator);
    }

    /**
     * Verify a membership proof against an expected Merkle root.
     *
     * @param proof        the membership proof
     * @param expectedRoot the expected Merkle root (e.g., from on-chain state)
     * @param material     the verification key material
     * @return verification result
     */
    public VerificationResult verify(MembershipProof proof, byte[] expectedRoot,
                                      VerificationMaterial material) {
        // Policy check: verify the proof is for the expected set
        if (!java.util.Arrays.equals(proof.merkleRoot(), expectedRoot)) {
            return VerificationResult.policyRejected(
                    VerificationResult.ReasonCode.STALE_STATE_ROOT,
                    "Merkle root does not match expected root");
        }

        // Cryptographic verification
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(proof.proofSystem())
                .curve(proof.curve())
                .circuitId(new CircuitId(proof.circuitId()))
                .proofBytes(proof.proofBytes())
                .publicInputs(new PublicInputs(proof.allPublicInputs()))
                .vkRef(new VerificationKeyRef.ById(proof.circuitId()))
                .build();

        return orchestrator.verify(envelope, material);
    }
}
