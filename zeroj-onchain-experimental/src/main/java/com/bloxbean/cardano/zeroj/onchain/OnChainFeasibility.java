package com.bloxbean.cardano.zeroj.onchain;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.util.List;

/**
 * Structured feasibility matrix for on-chain ZK proof verification on Cardano.
 *
 * <p>Provides a data-driven view of which proof system / curve combinations
 * are feasible for on-chain verification given Plutus V3 constraints.</p>
 *
 * <p>Cardano protocol parameters limit script execution to ~10B CPU units and ~14MB memory
 * per transaction (as of Chang hard fork). These limits determine feasibility.</p>
 */
public final class OnChainFeasibility {

    private OnChainFeasibility() {}

    /**
     * Feasibility status for an on-chain verification configuration.
     */
    public enum Status {
        /** Fully working and tested on testnet/mainnet. */
        WORKING,
        /** Experimental — prototype exists, not production-ready. */
        EXPERIMENTAL,
        /** Assessment only — theoretical analysis, no implementation. */
        ASSESSMENT_ONLY,
        /** Not feasible with current Plutus capabilities. */
        NOT_FEASIBLE
    }

    /**
     * A single entry in the feasibility matrix.
     */
    public record Entry(
            ProofSystemId proofSystem,
            CurveId curve,
            Status status,
            long estimatedCpuBudget,
            long estimatedMemoryBudget,
            String notes
    ) {}

    /**
     * Get the current feasibility matrix based on known implementations and estimates.
     */
    public static List<Entry> matrix() {
        return List.of(
                new Entry(ProofSystemId.GROTH16, CurveId.BLS12_381, Status.WORKING,
                        ScriptBudgetEstimator.estimateCpu(ProofSystemId.GROTH16, CurveId.BLS12_381, 1),
                        ScriptBudgetEstimator.estimateMemory(ProofSystemId.GROTH16, CurveId.BLS12_381, 1),
                        "Verified on Cardano preprod via Julc. ~2.4B CPU for 1 public input."),

                new Entry(ProofSystemId.PLONK, CurveId.BLS12_381, Status.EXPERIMENTAL,
                        ScriptBudgetEstimator.estimateCpu(ProofSystemId.PLONK, CurveId.BLS12_381, 1),
                        ScriptBudgetEstimator.estimateMemory(ProofSystemId.PLONK, CurveId.BLS12_381, 1),
                        "Feasible: Keccak_256 (CIP-0101, Chang HF) and Sha2_256 (Alonzo) both available in Plutus V3. "
                                + "snarkjs PlonK uses Keccak_256, gnark PlonK uses Sha2_256 for Fiat-Shamir."),

                new Entry(ProofSystemId.HALO2, CurveId.BLS12_381, Status.ASSESSMENT_ONLY,
                        -1, -1,
                        "KZG variant on BLS12-381. Very high cost due to many MSM operations."),

                new Entry(ProofSystemId.GROTH16, CurveId.BN254, Status.NOT_FEASIBLE,
                        -1, -1,
                        "No BN254 pairing builtins in Plutus V3. Cannot verify on-chain."),

                new Entry(ProofSystemId.PLONK, CurveId.BN254, Status.NOT_FEASIBLE,
                        -1, -1,
                        "No BN254 pairing builtins in Plutus V3. Cannot verify on-chain."),

                new Entry(ProofSystemId.HALO2, CurveId.PALLAS, Status.NOT_FEASIBLE,
                        -1, -1,
                        "No Pallas curve builtins in Plutus. IPA verification not implementable on-chain.")
        );
    }

    /**
     * Look up feasibility for a specific combination.
     */
    public static Entry lookup(ProofSystemId proofSystem, CurveId curve) {
        return matrix().stream()
                .filter(e -> e.proofSystem() == proofSystem && e.curve() == curve)
                .findFirst()
                .orElse(new Entry(proofSystem, curve, Status.NOT_FEASIBLE, -1, -1,
                        "Unknown combination — no assessment available."));
    }

    /**
     * Check if on-chain verification is feasible (WORKING or EXPERIMENTAL).
     */
    public static boolean isFeasible(ProofSystemId proofSystem, CurveId curve) {
        var entry = lookup(proofSystem, curve);
        return entry.status() == Status.WORKING || entry.status() == Status.EXPERIMENTAL;
    }
}
