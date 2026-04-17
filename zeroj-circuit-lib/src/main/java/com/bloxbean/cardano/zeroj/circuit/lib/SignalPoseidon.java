package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/**
 * Poseidon hash using the Signal API. Thin forwarder to {@link Poseidon}; see
 * there for preset selection and compile-field interop notes.
 *
 * <pre>{@code
 * Signal hash = SignalPoseidon.hash(c, params, left, right);
 * Signal hash = SignalPoseidon.hash(c, left, right);  // BN254 default
 * }</pre>
 */
public final class SignalPoseidon {

    private SignalPoseidon() {}

    /** Poseidon hash of two signals under the given {@link PoseidonParams}. */
    public static Signal hash(SignalBuilder c, PoseidonParams params, Signal input0, Signal input1) {
        return Poseidon.hash(c, params, input0, input1);
    }

    /** Poseidon hash of two signals under the back-compat BN254 default. */
    public static Signal hash(SignalBuilder c, Signal input0, Signal input1) {
        return Poseidon.hash(c, input0, input1);
    }
}
