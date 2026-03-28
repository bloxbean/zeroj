package com.bloxbean.cardano.zeroj.onchain;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

/**
 * Estimates on-chain execution budgets (CPU and memory) for ZK proof verification scripts.
 *
 * <p>Based on Plutus V3 BLS12-381 builtin costs from CIP-0381.
 * These are estimates — actual costs should be measured via {@code BudgetBenchmarkTest}
 * in zeroj-examples using the Julc VM.</p>
 *
 * <p>BN254 curves have no Plutus builtins, so on-chain verification is not feasible.</p>
 */
public final class ScriptBudgetEstimator {

    private ScriptBudgetEstimator() {}

    /**
     * Estimated CPU cost for a single BLS12-381 miller loop (Plutus V3 builtin).
     */
    public static final long MILLER_LOOP_CPU = 402_099_373L;

    /**
     * Estimated CPU cost for a BLS12-381 final verify (Plutus V3 builtin).
     */
    public static final long FINAL_VERIFY_CPU = 388_656_972L;

    /**
     * Estimated CPU cost for a BLS12-381 G1 scalar multiplication.
     */
    public static final long G1_SCALAR_MUL_CPU = 94_607_019L;

    /**
     * Estimated CPU cost for a BLS12-381 G1 addition.
     */
    public static final long G1_ADD_CPU = 1_046_420L;

    /**
     * Estimated CPU cost for a BLS12-381 G1 multi-scalar multiplication (MSM).
     * Per-element cost approximately.
     */
    public static final long G1_MSM_PER_ELEMENT_CPU = 80_000_000L;

    /**
     * Estimated CPU cost for blake2b_256 hash (Plutus builtin).
     */
    public static final long BLAKE2B_256_CPU = 2_477_736L;

    /**
     * Estimate the total CPU budget for on-chain verification.
     *
     * @param proofSystem   the proof system
     * @param curve         the elliptic curve
     * @param numPublicInputs number of public inputs
     * @return estimated CPU budget, or -1 if not feasible
     */
    public static long estimateCpu(ProofSystemId proofSystem, CurveId curve, int numPublicInputs) {
        if (curve != CurveId.BLS12_381) {
            return -1; // No on-chain builtins for BN254 or Pallas
        }

        return switch (proofSystem) {
            case GROTH16 -> estimateGroth16Cpu(numPublicInputs);
            case PLONK -> estimatePlonkCpu(numPublicInputs);
            default -> -1;
        };
    }

    /**
     * Estimate the total memory budget for on-chain verification.
     *
     * @param proofSystem   the proof system
     * @param curve         the elliptic curve
     * @param numPublicInputs number of public inputs
     * @return estimated memory in bytes, or -1 if not feasible
     */
    public static long estimateMemory(ProofSystemId proofSystem, CurveId curve, int numPublicInputs) {
        if (curve != CurveId.BLS12_381) {
            return -1;
        }

        return switch (proofSystem) {
            case GROTH16 -> estimateGroth16Memory(numPublicInputs);
            case PLONK -> estimatePlonkMemory(numPublicInputs);
            default -> -1;
        };
    }

    /**
     * Groth16 BLS12-381: e(A,B) * e(-alpha,beta) * e(-vk_x,gamma) * e(-C,delta) == 1
     * Cost: 4 miller loops + 1 final verify + (nPublic) G1 scalar muls + (nPublic) G1 adds
     */
    private static long estimateGroth16Cpu(int numPublicInputs) {
        return 4 * MILLER_LOOP_CPU
                + FINAL_VERIFY_CPU
                + numPublicInputs * G1_SCALAR_MUL_CPU
                + numPublicInputs * G1_ADD_CPU;
    }

    /**
     * PlonK BLS12-381: linearized commitment via MSM + 2 pairings + Fiat-Shamir hashing
     */
    private static long estimatePlonkCpu(int numPublicInputs) {
        int numMsmElements = 8 + numPublicInputs; // selectors + permutation + public
        return 2 * MILLER_LOOP_CPU
                + FINAL_VERIFY_CPU
                + numMsmElements * G1_MSM_PER_ELEMENT_CPU
                + 10 * G1_ADD_CPU
                + 6 * BLAKE2B_256_CPU; // Fiat-Shamir rounds
    }

    private static long estimateGroth16Memory(int numPublicInputs) {
        // Rough estimate: ~2MB base + 100KB per public input
        return 2_000_000L + numPublicInputs * 100_000L;
    }

    private static long estimatePlonkMemory(int numPublicInputs) {
        // PlonK needs more memory for commitments and challenges
        return 4_000_000L + numPublicInputs * 150_000L;
    }
}
