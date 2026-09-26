package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
