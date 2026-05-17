package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.util.List;

/**
 * Feasibility matrix for ZeroJ proof verification on Cardano Plutus V3.
 */
public final class OnChainFeasibility {

    private OnChainFeasibility() {}

    public enum Status {
        WORKING,
        EXPERIMENTAL,
        ASSESSMENT_ONLY,
        NOT_FEASIBLE
    }

    public record Entry(
            ProofSystemId proofSystem,
            CurveId curve,
            Status status,
            long estimatedCpuBudget,
            long estimatedMemoryBudget,
            String notes
    ) {}

    /**
     * Current implementation and feasibility view for proof-system / curve
     * combinations relevant to Cardano.
     */
    public static List<Entry> matrix() {
        return List.of(
                new Entry(ProofSystemId.GROTH16, CurveId.BLS12_381, Status.WORKING,
                        ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BLS12_381, 1),
                        ScriptBudgetEstimator.estimateMemory(ProofSystemId.GROTH16, CurveId.BLS12_381, 1),
                        "Shipping on-chain path via Julc and Plutus V3 BLS12-381 builtins."),

                new Entry(ProofSystemId.PLONK, CurveId.BLS12_381, Status.EXPERIMENTAL,
                        ScriptBudgetEstimator.estimateCpu(ProofSystemId.PLONK, CurveId.BLS12_381, 1),
                        ScriptBudgetEstimator.estimateMemory(ProofSystemId.PLONK, CurveId.BLS12_381, 1),
                        "Prototype only: transcript and inverse checks exist, but the KZG batch opening pairing check is deferred."),

                new Entry(ProofSystemId.HALO2, CurveId.BLS12_381, Status.ASSESSMENT_ONLY,
                        -1, -1,
                        "Research only; expected high cost due to MSM-heavy verification."),

                new Entry(ProofSystemId.GROTH16, CurveId.BN254, Status.NOT_FEASIBLE,
                        -1, -1,
                        "No BN254 pairing builtins in Plutus V3."),

                new Entry(ProofSystemId.PLONK, CurveId.BN254, Status.NOT_FEASIBLE,
                        -1, -1,
                        "No BN254 pairing builtins in Plutus V3."),

                new Entry(ProofSystemId.HALO2, CurveId.PALLAS, Status.NOT_FEASIBLE,
                        -1, -1,
                        "No Pallas curve builtins in Plutus V3.")
        );
    }

    public static Entry lookup(ProofSystemId proofSystem, CurveId curve) {
        return matrix().stream()
                .filter(e -> e.proofSystem() == proofSystem && e.curve() == curve)
                .findFirst()
                .orElse(new Entry(proofSystem, curve, Status.NOT_FEASIBLE, -1, -1,
                        "Unknown combination; no assessment available."));
    }

    public static boolean isFeasible(ProofSystemId proofSystem, CurveId curve) {
        var entry = lookup(proofSystem, curve);
        return entry.status() == Status.WORKING || entry.status() == Status.EXPERIMENTAL;
    }
}
