package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OnChainFeasibilityTest {

    @Test
    void marksBls12381Groth16WorkingAndPlonkExperimental() {
        var groth16 = OnChainFeasibility.lookup(ProofSystemId.GROTH16, CurveId.BLS12_381);
        var plonk = OnChainFeasibility.lookup(ProofSystemId.PLONK, CurveId.BLS12_381);

        assertEquals(OnChainFeasibility.Status.WORKING, groth16.status());
        assertEquals(OnChainFeasibility.Status.EXPERIMENTAL, plonk.status());
        assertTrue(OnChainFeasibility.isFeasible(ProofSystemId.GROTH16, CurveId.BLS12_381));
        assertTrue(OnChainFeasibility.isFeasible(ProofSystemId.PLONK, CurveId.BLS12_381));
    }

    @Test
    void marksBn254AsNotFeasibleOnCardano() {
        var entry = OnChainFeasibility.lookup(ProofSystemId.GROTH16, CurveId.BN254);

        assertEquals(OnChainFeasibility.Status.NOT_FEASIBLE, entry.status());
        assertFalse(OnChainFeasibility.isFeasible(ProofSystemId.GROTH16, CurveId.BN254));
    }

    @Test
    void unknownCombinationDefaultsToNotFeasible() {
        var entry = OnChainFeasibility.lookup(ProofSystemId.BBS, CurveId.BLS12_381);

        assertEquals(OnChainFeasibility.Status.NOT_FEASIBLE, entry.status());
    }
}
