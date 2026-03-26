package com.bloxbean.cardano.zeroj.patterns.nullifier;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;

import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Verifies a {@link NullifierClaim} and enforces nullifier uniqueness.
 *
 * <p>Combines cryptographic proof verification with double-spend prevention.
 * The nullifier is checked against a set of used nullifiers before and after verification.</p>
 */
public class NullifierClaimVerifier {

    private final VerifierOrchestrator orchestrator;
    private final Set<java.nio.ByteBuffer> usedNullifiers = ConcurrentHashMap.newKeySet();

    public NullifierClaimVerifier(VerifierOrchestrator orchestrator) {
        this.orchestrator = Objects.requireNonNull(orchestrator);
    }

    /**
     * Verify and accept a claim. Returns the verification result.
     *
     * <p>If the proof is valid and the nullifier hasn't been used, the nullifier is
     * marked as used and the claim is accepted. This is atomic — if two claims with
     * the same nullifier race, only one will succeed.</p>
     */
    public VerificationResult verifyAndAccept(NullifierClaim claim, VerificationMaterial material) {
        // Check nullifier hasn't been used
        var nullifierKey = java.nio.ByteBuffer.wrap(claim.nullifier());
        if (usedNullifiers.contains(nullifierKey)) {
            return VerificationResult.policyRejected(
                    VerificationResult.ReasonCode.USED_NULLIFIER,
                    "Nullifier already used");
        }

        // Build envelope and verify proof
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(claim.proofSystem())
                .curve(claim.curve())
                .circuitId(new CircuitId(claim.circuitId()))
                .proofBytes(claim.proofBytes())
                .publicInputs(new PublicInputs(claim.allPublicInputs()))
                .vkRef(new VerificationKeyRef.ById(claim.circuitId()))
                .build();

        var result = orchestrator.verify(envelope, material);
        if (!result.proofValid()) {
            return result;
        }

        // Atomically mark nullifier as used
        if (!usedNullifiers.add(java.nio.ByteBuffer.wrap(claim.nullifier().clone()))) {
            return VerificationResult.policyRejected(
                    VerificationResult.ReasonCode.USED_NULLIFIER,
                    "Nullifier already used (race condition)");
        }

        return VerificationResult.ok();
    }

    /**
     * Check if a nullifier has been used (read-only, no side effects).
     */
    public boolean isNullifierUsed(byte[] nullifier) {
        return usedNullifiers.contains(java.nio.ByteBuffer.wrap(nullifier));
    }
}
