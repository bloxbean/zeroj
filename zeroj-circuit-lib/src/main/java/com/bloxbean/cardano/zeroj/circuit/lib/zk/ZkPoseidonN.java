package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

import java.util.Objects;

/**
 * Symbolic variable-arity Poseidon adapter for annotation-based circuits.
 *
 * <p>This wrapper requires explicit {@link PoseidonParams}. The lower-level
 * {@link PoseidonN} no-params overload remains BN254 for backward
 * compatibility, but symbolic code should make the target field visible at the
 * call site.
 */
public final class ZkPoseidonN {

    private ZkPoseidonN() {}

    /**
     * Hash one or more symbolic field elements using folded two-input
     * Poseidon under the supplied parameters.
     *
     * <p>Single-input semantics match {@link PoseidonN}: {@code hash(x)} is
     * {@code Poseidon(x, 0)} under the same parameters.
     */
    public static ZkField hash(ZkContext zk, PoseidonParams params, ZkField... inputs) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(params, "params");
        Objects.requireNonNull(inputs, "inputs");
        if (inputs.length == 0) {
            throw new IllegalArgumentException("inputs must not be empty");
        }

        Signal[] signals = new Signal[inputs.length];
        for (int i = 0; i < inputs.length; i++) {
            ZkField input = Objects.requireNonNull(inputs[i], "inputs[" + i + "]");
            zk.requireSignal(input.signal());
            signals[i] = input.signal();
        }

        return ZkField.wrap(zk, PoseidonN.hash(zk.builder(), params, signals));
    }
}
