package com.bloxbean.cardano.zeroj.onchain.julc.analysis;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScriptBudgetEstimatorTest {

    @Test
    void estimatesGroth16Bls12381Budget() {
        long cpu = ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BLS12_381, 1);
        long memory = ScriptBudgetEstimator.estimateMemory(ProofSystemId.GROTH16, CurveId.BLS12_381, 1);

        assertTrue(cpu > 0);
        assertTrue(memory > 0);
    }

    @Test
    void estimatesPlonkAsMoreCpuIntensiveThanGroth16() {
        long grothCpu = ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BLS12_381, 1);
        long plonkCpu = ScriptBudgetEstimator.estimateCpu(ProofSystemId.PLONK, CurveId.BLS12_381, 1);

        assertTrue(plonkCpu > grothCpu);
        assertTrue(plonkCpu < 10_000_000_000L);
    }

    @Test
    void returnsMinusOneForNonCardanoCurves() {
        assertEquals(-1, ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BN254, 1));
        assertEquals(-1, ScriptBudgetEstimator.estimateMemory(ProofSystemId.GROTH16, CurveId.BN254, 1));
    }

    @Test
    void rejectsNegativePublicInputCounts() {
        assertThrows(IllegalArgumentException.class,
                () -> ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BLS12_381, -1));
        assertThrows(IllegalArgumentException.class,
                () -> ScriptBudgetEstimator.estimateMemory(ProofSystemId.GROTH16, CurveId.BLS12_381, -1));
    }
}
