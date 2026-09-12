package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves canonical JMT insertion by splitting an authenticated conflicting leaf. */
public final class ZkJmtInsertDifferentLeaf {
    private ZkJmtInsertDifferentLeaf() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> queryNibbles, ZkField insertedValueHash,
            ZkArray<ZkUInt> conflictingNibbles, ZkField conflictingValueHash,
            ZkField oldRoot, ZkField newRoot,
            ZkJmtPathProof proof) {
        ZkJmt.Prepared query = ZkJmt.prepare(zk, params, queryNibbles, proof);
        ZkField conflictingKey = ZkJmtCanonicalKey.decode(zk, conflictingNibbles);
        ZkJmt.assertDifferentLeaf(zk, query, conflictingNibbles, conflictingKey);
        ZkField oldLeaf = ZkJmt.leaf(zk, params, conflictingKey, conflictingValueHash);
        ZkField queryLeaf = ZkJmt.leaf(zk, params, query.key(), insertedValueHash);
        ZkField newTerminal = ZkJmt.differentLeafInsertionTerminal(
                zk, params, query, queryLeaf, conflictingNibbles, oldLeaf);
        ZkField[] roots = ZkJmt.rootsFromTerminals(
                zk, params, query, oldLeaf, newTerminal);
        roots[0].assertEqual(oldRoot);
        roots[1].assertEqual(newRoot);
    }
}
