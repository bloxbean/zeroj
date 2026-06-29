package com.bloxbean.cardano.zeroj.patterns;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;

/**
 * Pre-built verification policy templates for common ZK patterns.
 * <p>
 * These combine proof system requirements, curve constraints, and minimum
 * public input counts into ready-to-use policies.
 * <p>
 * Example:
 * <pre>{@code
 * // Standard Groth16/BLS12-381 state transition policy
 * var policy = PatternPolicies.stateTransition(orchestrator);
 * var result = policy.evaluate(envelope, material);
 *
 * // BLS12-381 membership policy
 * var policy = PatternPolicies.groth16Bls12381(orchestrator, 2);
 * }</pre>
 */
public final class PatternPolicies {

    private PatternPolicies() {}

    /**
     * State transition policy: Groth16/BLS12-381, minimum 2 public inputs
     * (old state hash + new state hash).
     */
    public static VerificationPolicyTemplate stateTransition(VerifierOrchestrator orchestrator) {
        return VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BLS12_381)
                .requireMinPublicInputs(2)
                .build();
    }

    /**
     * State transition policy for BLS12-381 circuits.
     */
    public static VerificationPolicyTemplate stateTransitionBls12381(VerifierOrchestrator orchestrator) {
        return VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BLS12_381)
                .requireMinPublicInputs(2)
                .build();
    }

    /**
     * Nullifier claim policy: Groth16/BLS12-381, minimum 1 public input (claim value).
     */
    public static VerificationPolicyTemplate nullifierClaim(VerifierOrchestrator orchestrator) {
        return VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BLS12_381)
                .requireMinPublicInputs(1)
                .build();
    }

    /**
     * Membership proof policy: Groth16/BLS12-381, minimum 1 public input (constraint output).
     */
    public static VerificationPolicyTemplate membership(VerifierOrchestrator orchestrator) {
        return VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BLS12_381)
                .requireMinPublicInputs(1)
                .build();
    }

    /**
     * Legacy off-chain Groth16/BN254 policy with configurable minimum public inputs.
     */
    @Deprecated(forRemoval = true)
    public static VerificationPolicyTemplate groth16Bn254(VerifierOrchestrator orchestrator, int minPublicInputs) {
        return VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BN254)
                .requireMinPublicInputs(minPublicInputs)
                .build();
    }

    /**
     * Generic Groth16/BLS12-381 policy with configurable minimum public inputs.
     */
    public static VerificationPolicyTemplate groth16Bls12381(VerifierOrchestrator orchestrator, int minPublicInputs) {
        return VerificationPolicyTemplate.create(orchestrator)
                .requireProofSystem(ProofSystemId.GROTH16)
                .requireCurve(CurveId.BLS12_381)
                .requireMinPublicInputs(minPublicInputs)
                .build();
    }
}
