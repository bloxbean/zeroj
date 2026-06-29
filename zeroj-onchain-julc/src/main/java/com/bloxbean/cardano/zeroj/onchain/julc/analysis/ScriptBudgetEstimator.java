package com.bloxbean.cardano.zeroj.onchain.julc.analysis;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

/**
 * Estimates Cardano Plutus V3 execution budgets for ZeroJ on-chain verifiers.
 *
 * <p>The constants are conservative estimates based on BLS12-381 builtin costs.
 * Actual budgets should still be measured with the Julc VM and a representative
 * transaction before mainnet deployment.</p>
 */
public final class ScriptBudgetEstimator {

    private ScriptBudgetEstimator() {}

    public static final long MILLER_LOOP_CPU = 402_099_373L;
    public static final long FINAL_VERIFY_CPU = 388_656_972L;
    public static final long G1_SCALAR_MUL_CPU = 94_607_019L;
    public static final long G1_ADD_CPU = 1_046_420L;
    public static final long G1_MSM_PER_ELEMENT_CPU = 80_000_000L;
    public static final long BLAKE2B_256_CPU = 2_477_736L;
    public static final long PLONK_BLS12381_ONE_INPUT_MEASURED_CPU = 4_802_500_000L;
    public static final long PLONK_BLS12381_ONE_INPUT_MEASURED_MEMORY = 865_000L;
    public static final int PLONK_BLS12381_MPI_MAX_PUBLIC_INPUTS = 8;
    public static final long PLONK_BLS12381_MPI_ONE_INPUT_MEASURED_CPU = 4_810_200_000L;
    public static final long PLONK_BLS12381_MPI_ONE_INPUT_MEASURED_MEMORY = 905_000L;
    public static final long PLONK_BLS12381_MPI_PER_EXTRA_INPUT_CPU = 20_000_000L;
    public static final long PLONK_BLS12381_MPI_PER_EXTRA_INPUT_MEMORY = 65_000L;

    /**
     * Estimate CPU units for on-chain verification, or {@code -1} when the
     * proof system / curve combination is not feasible on Plutus V3.
     */
    public static long estimateCpu(ProofSystemId proofSystem, CurveId curve, int numPublicInputs) {
        if (numPublicInputs < 0) {
            throw new IllegalArgumentException("numPublicInputs must be non-negative");
        }
        if (curve != CurveId.BLS12_381) {
            return -1;
        }

        return switch (proofSystem) {
            case GROTH16 -> estimateGroth16Cpu(numPublicInputs);
            case PLONK -> estimatePlonkCpu(numPublicInputs);
            default -> -1;
        };
    }

    /**
     * Estimate memory units for on-chain verification, or {@code -1} when the
     * proof system / curve combination is not feasible on Plutus V3.
     */
    public static long estimateMemory(ProofSystemId proofSystem, CurveId curve, int numPublicInputs) {
        if (numPublicInputs < 0) {
            throw new IllegalArgumentException("numPublicInputs must be non-negative");
        }
        if (curve != CurveId.BLS12_381) {
            return -1;
        }

        return switch (proofSystem) {
            case GROTH16 -> estimateGroth16Memory(numPublicInputs);
            case PLONK -> estimatePlonkMemory(numPublicInputs);
            default -> -1;
        };
    }

    private static long estimateGroth16Cpu(int numPublicInputs) {
        return 4 * MILLER_LOOP_CPU
                + FINAL_VERIFY_CPU
                + numPublicInputs * G1_SCALAR_MUL_CPU
                + numPublicInputs * G1_ADD_CPU;
    }

    private static long estimatePlonkCpu(int numPublicInputs) {
        if (numPublicInputs < 1 || numPublicInputs > PLONK_BLS12381_MPI_MAX_PUBLIC_INPUTS) {
            return -1;
        }
        if (numPublicInputs > 1) {
            return PLONK_BLS12381_MPI_ONE_INPUT_MEASURED_CPU
                    + (long) (numPublicInputs - 1) * PLONK_BLS12381_MPI_PER_EXTRA_INPUT_CPU;
        }
        return PLONK_BLS12381_ONE_INPUT_MEASURED_CPU
                + Math.max(0, numPublicInputs - 1) * PLONK_BLS12381_MPI_PER_EXTRA_INPUT_CPU;
    }

    private static long estimateGroth16Memory(int numPublicInputs) {
        return 2_000_000L + numPublicInputs * 100_000L;
    }

    private static long estimatePlonkMemory(int numPublicInputs) {
        if (numPublicInputs < 1 || numPublicInputs > PLONK_BLS12381_MPI_MAX_PUBLIC_INPUTS) {
            return -1;
        }
        if (numPublicInputs > 1) {
            return PLONK_BLS12381_MPI_ONE_INPUT_MEASURED_MEMORY
                    + (long) (numPublicInputs - 1) * PLONK_BLS12381_MPI_PER_EXTRA_INPUT_MEMORY;
        }
        return PLONK_BLS12381_ONE_INPUT_MEASURED_MEMORY
                + Math.max(0, numPublicInputs - 1) * PLONK_BLS12381_MPI_PER_EXTRA_INPUT_MEMORY;
    }
}
