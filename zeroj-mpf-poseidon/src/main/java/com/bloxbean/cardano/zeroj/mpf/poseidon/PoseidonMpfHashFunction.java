package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.core.api.HashFunction;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.util.Objects;

/**
 * CCL {@link HashFunction} backed by the ZeroJ BLS12-381 Poseidon MPF digest.
 */
public final class PoseidonMpfHashFunction implements HashFunction {
    public static final PoseidonMpfHashFunction INSTANCE =
            new PoseidonMpfHashFunction(PoseidonParamsBLS12_381T3.INSTANCE);

    private final PoseidonParams params;

    public PoseidonMpfHashFunction(PoseidonParams params) {
        PoseidonMpfHash.requireBlsParams(params);
        this.params = Objects.requireNonNull(params, "params");
    }

    public PoseidonParams params() {
        return params;
    }

    @Override
    public byte[] digest(byte[] in) {
        return PoseidonMpfHash.digest(params, in);
    }
}
