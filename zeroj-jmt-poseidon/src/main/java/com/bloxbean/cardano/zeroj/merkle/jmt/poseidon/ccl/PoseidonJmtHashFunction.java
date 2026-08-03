package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.core.api.HashFunction;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;

import java.util.Objects;

/** CCL {@link HashFunction} adapter for the Poseidon JMT v1 byte profile. */
public final class PoseidonJmtHashFunction implements HashFunction {
    @Override
    public byte[] digest(byte[] input) {
        return PoseidonJmtHash.digest(Objects.requireNonNull(input, "input"));
    }
}
