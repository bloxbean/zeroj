package org.zeroj.mpf.load;

import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.merkle.mpf.poseidon.circuit.PoseidonMpfCircuitTemplates;

/** The exact inclusion circuit benchmarked by the load tool. */
final class PoseidonMpfInclusionCircuit {
    private PoseidonMpfInclusionCircuit() {}

    static CircuitBuilder build(int maxSteps) {
        return PoseidonMpfCircuitTemplates.inclusion(maxSteps);
    }
}
