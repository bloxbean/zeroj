package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves canonical insertion into an authenticated empty JMT child. */
public final class ZkJmtInsertEmpty {
    private ZkJmtInsertEmpty() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles, ZkField insertedValueHash,
            ZkField oldRoot, ZkField newRoot,
            ZkJmtPathProof proof) {
        ZkJmt.Prepared prepared = ZkJmt.prepare(zk, params, keyNibbles, proof);
        ZkField insertedLeaf = ZkJmt.leaf(zk, params, prepared.key(), insertedValueHash);
        ZkField[] roots = ZkJmt.rootsFromTerminals(
                zk, params, prepared, ZkJmt.empty(zk), insertedLeaf);
        roots[0].assertEqual(oldRoot);
        roots[1].assertEqual(newRoot);
    }
}
