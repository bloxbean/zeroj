package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;

/**
 * MiMC Sponge construction — variable-length input hashing using MiMC-7 as the permutation.
 *
 * <p>The sponge absorbs an arbitrary number of field elements and squeezes one or more
 * output elements. Uses a rate of 1 and capacity of 1 (state width = 2).</p>
 *
 * <p>Algorithm (matching iden3/circomlib MiMCSponge):
 * <ol>
 *   <li>Initialize state: [0, 0]</li>
 *   <li>Absorb phase: for each input, state[0] += input, then permute via MiMC</li>
 *   <li>Squeeze phase: output state[0], permute, repeat for nOutputs</li>
 * </ol>
 *
 * <p>Constraint cost: ~364 per absorption (one MiMC-7 invocation per input element).</p>
 *
 * <p>Circom equivalent: {@code MiMCSponge(nInputs, nRounds, nOutputs)} from circomlib.</p>
 */
public final class MiMCSponge {

    private MiMCSponge() {}

    /**
     * Hash variable-length input to a single output.
     *
     * @param api    circuit API
     * @param inputs array of field elements to hash (length >= 1)
     * @return single hash output
     */
    public static Variable hash(CircuitAPI api, Variable[] inputs) {
        return hashMulti(api, inputs, 1)[0];
    }

    /**
     * Hash variable-length input with multiple squeeze outputs.
     *
     * @param api      circuit API
     * @param inputs   array of field elements to absorb (length >= 1)
     * @param nOutputs number of output elements to squeeze (>= 1)
     * @return array of output field elements
     */
    public static Variable[] hashMulti(CircuitAPI api, Variable[] inputs, int nOutputs) {
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");
        if (nOutputs < 1) throw new IllegalArgumentException("nOutputs must be >= 1");

        // State: [left, right] — rate=1 (left), capacity=1 (right)
        Variable left = api.constant(0);
        Variable right = api.constant(0);

        // Absorb phase: add input into rate (left), then Feistel permute
        for (Variable input : inputs) {
            left = api.add(left, input);
            // Feistel permutation: left' = MiMC(left, right) + right, right' = left (pre-MiMC)
            // This matches circomlib MiMCSponge Feistel construction
            Variable oldLeft = left;
            Variable mimc = MiMC.hash(api, left, right);
            left = api.add(mimc, right);
            right = oldLeft;
        }

        // Squeeze phase: output left, then Feistel permute for additional outputs
        Variable[] outputs = new Variable[nOutputs];
        outputs[0] = left;
        for (int i = 1; i < nOutputs; i++) {
            Variable oldLeft = left;
            Variable mimc = MiMC.hash(api, left, right);
            left = api.add(mimc, right);
            right = oldLeft;
            outputs[i] = left;
        }

        return outputs;
    }

    // --- Signal API wrappers ---

    public static Signal hash(SignalBuilder c, Signal[] inputs) {
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) vars[i] = inputs[i].variable();
        return c.wrap(hash(c.api(), vars));
    }

    public static Signal[] hashMulti(SignalBuilder c, Signal[] inputs, int nOutputs) {
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) vars[i] = inputs[i].variable();
        Variable[] results = hashMulti(c.api(), vars, nOutputs);
        Signal[] signals = new Signal[results.length];
        for (int i = 0; i < results.length; i++) signals[i] = c.wrap(results[i]);
        return signals;
    }
}
