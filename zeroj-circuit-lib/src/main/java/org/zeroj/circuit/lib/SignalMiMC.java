package org.zeroj.circuit.lib;

import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * <b>DEPRECATED FOR REMOVAL — INSECURE / INVERTIBLE — DO NOT USE.</b>
 *
 * <p>Signal API copy of {@link MiMC}: computes an invertible keyed bijection {@code E_right(left)}
 * without feed-forward on BN254. Preimages and Merkle membership proofs are trivially forgeable.
 * Use {@link SignalPoseidon#hash(SignalBuilder, PoseidonParams, Signal, Signal)} with
 * {@link PoseidonParamsBLS12_381T3#INSTANCE} on BLS12-381 instead.</p>
 *
 * @deprecated Scheduled for removal because the underlying permutation omits feed-forward and is
 *             trivially invertible. Use
 *             {@link SignalPoseidon#hash(SignalBuilder, PoseidonParams, Signal, Signal)} with
 *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
 */
@Deprecated(forRemoval = true)
@SuppressWarnings("removal")
public final class SignalMiMC {

    private SignalMiMC() {}

    private static final int NUM_ROUNDS = 91;

    /**
     * <b>INSECURE:</b> Invertible MiMC-7 keyed bijection on BN254. Do not use.
     *
     * @deprecated Scheduled for removal. Use
     *             {@link SignalPoseidon#hash(SignalBuilder, PoseidonParams, Signal, Signal)} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
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
