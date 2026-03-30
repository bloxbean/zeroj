package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;

import java.math.BigInteger;

/**
 * Variable-arity Poseidon hash — supports 1 to 5 inputs (t = nInputs + 1).
 *
 * <p>The standard Poseidon(2) uses t=3 (2 inputs + 1 capacity). This implementation
 * generalizes to any width by varying the state size and corresponding constants.</p>
 *
 * <p>For t=3 (2 inputs), this delegates to the existing optimized {@link Poseidon} with
 * pre-loaded constants from circomlibjs. For other arities, it uses a sequential
 * approach: hash pairs using the 2-input Poseidon in a left-fold pattern.</p>
 *
 * <p>This matches the practical approach used by most ZK applications:
 * {@code PoseidonN(a, b, c, d) = Poseidon(Poseidon(Poseidon(a, b), c), d)}</p>
 *
 * <p>Note: a true variable-width Poseidon would use different MDS matrices and
 * round constants per arity. The folded approach is safe and widely used but
 * produces ~330 constraints per pair (not per element).</p>
 *
 * <p>Circom equivalent: {@code Poseidon(nInputs)} from circomlib.</p>
 */
public final class PoseidonN {

    private PoseidonN() {}

    /**
     * Hash N inputs using Poseidon (folded 2-input approach).
     *
     * @param api    circuit API
     * @param inputs 1 to N field elements
     * @return hash output
     */
    public static Variable hash(CircuitAPI api, Variable... inputs) {
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");
        if (inputs.length == 1) {
            // Single input: hash with zero
            return Poseidon.hash(api, inputs[0], api.constant(0));
        }
        if (inputs.length == 2) {
            // Optimal: direct 2-input Poseidon
            return Poseidon.hash(api, inputs[0], inputs[1]);
        }
        // N > 2: left-fold — Poseidon(Poseidon(...Poseidon(in[0], in[1])..., in[n-2]), in[n-1])
        Variable acc = Poseidon.hash(api, inputs[0], inputs[1]);
        for (int i = 2; i < inputs.length; i++) {
            acc = Poseidon.hash(api, acc, inputs[i]);
        }
        return acc;
    }

    /**
     * Hash N inputs using Poseidon. Signal API wrapper.
     */
    public static Signal hash(SignalBuilder c, Signal... inputs) {
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) vars[i] = inputs[i].variable();
        return c.wrap(hash(c.api(), vars));
    }
}
