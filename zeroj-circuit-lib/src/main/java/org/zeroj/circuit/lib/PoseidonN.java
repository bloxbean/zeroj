package org.zeroj.circuit.lib;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBN254T3;

import java.util.Objects;

/**
 * Fixed-arity folded Poseidon hash — left-folds pairs through the two-input
 * {@link Poseidon} gadget:
 * {@code PoseidonN(a, b, c, d) = Poseidon(Poseidon(Poseidon(a, b), c), d)}.
 *
 * <p><b>Security warning (fixed-arity only — not domain-separated across lengths):</b>
 * Because this construction folds without encoding input length or arity, distinct input
 * tuples of different lengths collide trivially:
 * <ul>
 *   <li>{@code PoseidonN(x) == Poseidon(x, 0) == PoseidonN(x, 0)}</li>
 *   <li>{@code PoseidonN(a, b, c) == Poseidon(Poseidon(a, b), c) == PoseidonN(Poseidon(a, b), c)}</li>
 * </ul>
 * Never accept variable-length inputs under the same commitment or hash domain without
 * prepending an explicit domain separator and length tag.</p>
 *
 * <p><b>Interop note:</b> This is <em>not</em> equivalent to circomlib's {@code Poseidon(nInputs)},
 * which uses a width-{@code (nInputs + 1)} permutation with arity-specific MDS matrices and round
 * constants. All overloads forward to two-input {@link Poseidon}; pass explicit
 * {@link PoseidonParams} (e.g. {@link org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3#INSTANCE})
 * for BLS12-381 circuits.</p>
 */
public final class PoseidonN {

    private PoseidonN() {}

    /**
     * Hash a fixed-arity tuple of inputs under the given {@link PoseidonParams} using left-folded
     * two-input Poseidon.
     *
     * <p>Single-input semantics: {@code PoseidonN(x) == Poseidon(x, 0)} (collides with 2-input
     * {@code PoseidonN(x, 0)}). Callers requiring cross-arity domain separation must prepend an
     * explicit domain tag and arity element.</p>
     */
    public static Variable hash(CircuitAPI api, PoseidonParams params, Variable... inputs) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(inputs, "inputs");
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");
        for (int i = 0; i < inputs.length; i++) {
            Objects.requireNonNull(inputs[i], "inputs[" + i + "]");
        }
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
        Objects.requireNonNull(c, "c");
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(inputs, "inputs");
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            Signal input = Objects.requireNonNull(inputs[i], "inputs[" + i + "]");
            if (!input.isFrom(c)) {
                throw new IllegalArgumentException(
                        "inputs[" + i + "] does not belong to the given SignalBuilder");
            }
            vars[i] = input.variable();
        }
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
