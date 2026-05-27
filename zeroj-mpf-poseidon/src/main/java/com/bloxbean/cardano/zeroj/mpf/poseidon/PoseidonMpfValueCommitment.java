package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;

/**
 * Host-side helpers for values stored in the Poseidon MPF profile.
 */
public final class PoseidonMpfValueCommitment {
    private PoseidonMpfValueCommitment() {}

    public static byte[] digest(byte[] value) {
        return digest(PoseidonParamsBLS12_381T3.INSTANCE, value);
    }

    public static byte[] digest(PoseidonParams params, byte[] value) {
        return new PoseidonMpfHashFunction(params).digest(value);
    }

    public static BigInteger field(byte[] value) {
        return field(PoseidonParamsBLS12_381T3.INSTANCE, value);
    }

    public static BigInteger field(PoseidonParams params, byte[] value) {
        return PoseidonMpfHash.fieldFromDigestBytes(digest(params, value));
    }
}
