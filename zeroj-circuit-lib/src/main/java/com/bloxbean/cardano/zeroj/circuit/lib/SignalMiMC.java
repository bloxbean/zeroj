package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

/**
 * MiMC hash using the Signal API.
 *
 * <pre>{@code
 * Signal hash = SignalMiMC.hash(c, left, right);
 * }</pre>
 */
public final class SignalMiMC {

    private SignalMiMC() {}

    private static final int NUM_ROUNDS = 91;

    /**
     * MiMC-7 hash of two signals.
     */
    public static Signal hash(SignalBuilder c, Signal left, Signal right) {
        c.api().requireField(FieldConfig.BN254);

        Signal state = left;
        Signal key = right;

        for (int i = 0; i < NUM_ROUNDS; i++) {
            // t = state + roundConstant + key
            Signal rc = c.constant(MiMC.roundConstant(i));
            Signal t = state.add(rc).add(key);

            // t^7 = ((t^2)^2 * t^2) * t
            Signal t2 = t.mul(t);
            Signal t4 = t2.mul(t2);
            Signal t6 = t4.mul(t2);
            state = t6.mul(t);
        }

        return state.add(key);
    }
}
