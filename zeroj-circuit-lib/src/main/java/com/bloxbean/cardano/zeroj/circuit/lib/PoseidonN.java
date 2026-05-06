package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBN254T3;

/**
 * Variable-arity Poseidon hash — left-folds pairs through the two-input
 * {@link Poseidon} gadget.
 *
 * <p>{@code PoseidonN(a, b, c, d) = Poseidon(Poseidon(Poseidon(a, b), c), d)}
 *
 * <p>This is the practical approach used by most ZK applications: simple,
 * widely compatible, and produces ~330 constraints per pair rather than per
 * element. A true variable-width Poseidon would use separate MDS matrices
 * and round constants per arity; we do not support that today.
 *
 * <p>All overloads forward to {@link Poseidon}; see there for param/preset
 * selection and interop notes.
 *
 * <p>Circom equivalent: {@code Poseidon(nInputs)} from circomlib (folded).
 */
public final class PoseidonN {

    private PoseidonN() {}

    /**
     * Hash N inputs under the given {@link PoseidonParams} using folded two-input
     * Poseidon.
     *
     * <p>Single-input semantics: {@code PoseidonN(x) == Poseidon(x, 0)}. This
     * is a ZeroJ-specific convention (no published Poseidon spec defines a
     * 1-arity case). If spec interop with an external 1-input Poseidon is
     * required, hash {@code (x, 0)} explicitly.
     */
    public static Variable hash(CircuitAPI api, PoseidonParams params, Variable... inputs) {
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");
        if (inputs.length == 1) {
            return Poseidon.hash(api, params, inputs[0], api.constant(0));
        }
        Variable acc = Poseidon.hash(api, params, inputs[0], inputs[1]);
        for (int i = 2; i < inputs.length; i++) {
            acc = Poseidon.hash(api, params, acc, inputs[i]);
        }
        return acc;
    }

    /** Signal-API variant. */
    public static Signal hash(SignalBuilder c, PoseidonParams params, Signal... inputs) {
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) vars[i] = inputs[i].variable();
        return c.wrap(hash(c.api(), params, vars));
    }

    /** Hash N inputs under the back-compat default ({@link PoseidonParamsBN254T3#INSTANCE}). */
    public static Variable hash(CircuitAPI api, Variable... inputs) {
        return hash(api, PoseidonParamsBN254T3.INSTANCE, inputs);
    }

    /** Signal-API variant of the back-compat-default hash. */
    public static Signal hash(SignalBuilder c, Signal... inputs) {
        return hash(c, PoseidonParamsBN254T3.INSTANCE, inputs);
    }
}
