package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves an existing JMT leaf value replacement from oldRoot to newRoot. */
public final class ZkJmtValueUpdate {
    private ZkJmtValueUpdate() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles,
            ZkField oldValueHash, ZkField newValueHash,
            ZkField oldRoot, ZkField newRoot,
            ZkJmtPathProof proof) {
        oldValueHash.isEqual(newValueHash).assertFalse();
        ZkJmt.Prepared prepared = ZkJmt.prepare(zk, params, keyNibbles, proof);
        ZkField oldLeaf = ZkJmt.leaf(zk, params, prepared.key(), oldValueHash);
        ZkField newLeaf = ZkJmt.leaf(zk, params, prepared.key(), newValueHash);
        ZkField[] roots = ZkJmt.rootsFromTerminals(zk, params, prepared, oldLeaf, newLeaf);
        roots[0].assertEqual(oldRoot);
        roots[1].assertEqual(newRoot);
    }
}
