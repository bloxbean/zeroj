package org.zeroj.circuit.lib;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * <b>DEPRECATED FOR REMOVAL — INSECURE — DO NOT USE.</b>
 *
 * <p>This gadget delegates to {@link MiMC#hash}, which computes a broken, non-standard BN254
 * permutation with SHA-256 round constants rather than circomlib's Feistel/Keccak-256 MiMCSponge.
 * <b>It is NOT compatible with {@code iden3/circomlib} {@code MiMCSponge}</b> and should not be
 * used for any cryptographic purpose.</p>
 *
 * <p>Use {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} (or
 * {@link PoseidonN#hash(CircuitAPI, PoseidonParams, Variable[])} for fixed-arity inputs) with
 * {@link PoseidonParamsBLS12_381T3#INSTANCE} on BLS12-381 instead.</p>
 *
 * @deprecated Scheduled for removal. Inherits the broken {@link MiMC} construction and is not
 *             circomlib-compatible. Use
 *             {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} or
 *             {@link PoseidonN#hash(CircuitAPI, PoseidonParams, Variable[])} with
 *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
 */
@Deprecated(forRemoval = true)
@SuppressWarnings("removal")
public final class MiMCSponge {

    private MiMCSponge() {}

    /**
     * @deprecated Scheduled for removal. Use
     *             {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} or
     *             {@link PoseidonN#hash(CircuitAPI, PoseidonParams, Variable[])} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
    public static Variable hash(CircuitAPI api, Variable[] inputs) {
        return hashMulti(api, inputs, 1)[0];
    }

    /**
     * @deprecated Scheduled for removal. Use
     *             {@link Poseidon#hash(CircuitAPI, PoseidonParams, Variable, Variable)} or
     *             {@link PoseidonN#hash(CircuitAPI, PoseidonParams, Variable[])} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
    public static Variable[] hashMulti(CircuitAPI api, Variable[] inputs, int nOutputs) {
        if (inputs.length == 0) throw new IllegalArgumentException("inputs must not be empty");
        if (nOutputs < 1) throw new IllegalArgumentException("nOutputs must be >= 1");

        // State: [left, right] — rate=1 (left), capacity=1 (right)
        Variable left = api.constant(0);
        Variable right = api.constant(0);

        // Absorb phase: add input into rate (left), then apply deprecated MiMC round function
        for (Variable input : inputs) {
            left = api.add(left, input);
            Variable oldLeft = left;
            Variable mimc = MiMC.hash(api, left, right);
            left = api.add(mimc, right);
            right = oldLeft;
        }

        // Squeeze phase: output left, then permute for additional outputs
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

    /**
     * @deprecated Scheduled for removal. Use
     *             {@link SignalPoseidon#hash(SignalBuilder, PoseidonParams, Signal, Signal)} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
    public static Signal hash(SignalBuilder c, Signal[] inputs) {
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) vars[i] = inputs[i].variable();
        return c.wrap(hash(c.api(), vars));
    }

    /**
     * @deprecated Scheduled for removal. Use
     *             {@link SignalPoseidon#hash(SignalBuilder, PoseidonParams, Signal, Signal)} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
    public static Signal[] hashMulti(SignalBuilder c, Signal[] inputs, int nOutputs) {
        Variable[] vars = new Variable[inputs.length];
        for (int i = 0; i < inputs.length; i++) vars[i] = inputs[i].variable();
        Variable[] results = hashMulti(c.api(), vars, nOutputs);
        Signal[] signals = new Signal[results.length];
        for (int i = 0; i < results.length; i++) signals[i] = c.wrap(results[i]);
        return signals;
    }
}
