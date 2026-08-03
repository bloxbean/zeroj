package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves that one full key maps to one value hash under a Poseidon JMT v1 root. */
public final class ZkJmtInclusion {
    private ZkJmtInclusion() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles, ZkField valueHash,
            ZkField expectedRoot, ZkJmtPathProof proof) {
        ZkJmt.Prepared prepared = ZkJmt.prepare(zk, params, keyNibbles, proof);
        ZkField terminal = ZkJmt.leaf(zk, params, prepared.key(), valueHash);
        ZkJmt.rootFromTerminal(zk, params, prepared, terminal).assertEqual(expectedRoot);
    }
}
