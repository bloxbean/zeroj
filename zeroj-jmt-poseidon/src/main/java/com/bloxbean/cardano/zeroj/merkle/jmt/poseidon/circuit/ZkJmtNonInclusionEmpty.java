package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves that a full key path reaches an authenticated empty JMT child. */
public final class ZkJmtNonInclusionEmpty {
    private ZkJmtNonInclusionEmpty() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles, ZkField expectedRoot, ZkJmtPathProof proof) {
        ZkJmt.Prepared prepared = ZkJmt.prepare(zk, params, keyNibbles, proof);
        ZkJmt.rootFromTerminal(zk, params, prepared, ZkJmt.empty(zk)).assertEqual(expectedRoot);
    }
}
