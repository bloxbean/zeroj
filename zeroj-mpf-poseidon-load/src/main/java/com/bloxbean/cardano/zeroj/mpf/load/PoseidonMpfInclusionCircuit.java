package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit.PoseidonMpfCircuitTemplates;

/** The exact inclusion circuit benchmarked by the load tool. */
final class PoseidonMpfInclusionCircuit {
    private PoseidonMpfInclusionCircuit() {}

    static CircuitBuilder build(int maxSteps) {
        return PoseidonMpfCircuitTemplates.inclusion(maxSteps);
    }
}
