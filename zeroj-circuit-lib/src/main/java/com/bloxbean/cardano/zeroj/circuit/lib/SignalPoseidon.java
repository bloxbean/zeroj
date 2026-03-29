package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

/**
 * Poseidon hash using the Signal API.
 *
 * <pre>{@code
 * Signal hash = SignalPoseidon.hash(c, left, right);
 * }</pre>
 */
public final class SignalPoseidon {

    private SignalPoseidon() {}

    /**
     * Poseidon hash of two signals.
     */
    public static Signal hash(SignalBuilder c, Signal input0, Signal input1) {
        return Poseidon.hash(c, input0, input1);
    }
}
