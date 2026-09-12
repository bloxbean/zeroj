package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
