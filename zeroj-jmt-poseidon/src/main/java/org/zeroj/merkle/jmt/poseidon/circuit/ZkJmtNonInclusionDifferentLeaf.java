package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves absence through a fully authenticated different JMT leaf. */
public final class ZkJmtNonInclusionDifferentLeaf {
    private ZkJmtNonInclusionDifferentLeaf() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> queryNibbles,
            ZkArray<ZkUInt> conflictingNibbles,
            ZkField conflictingValueHash,
            ZkField expectedRoot,
            ZkJmtPathProof proof) {
        ZkJmt.Prepared query = ZkJmt.prepare(zk, params, queryNibbles, proof);
        ZkField conflictingKey = ZkJmtCanonicalKey.decode(zk, conflictingNibbles);
        ZkJmt.assertDifferentLeaf(zk, query, conflictingNibbles, conflictingKey);
        ZkField terminal = ZkJmt.leaf(zk, params, conflictingKey, conflictingValueHash);
        ZkJmt.rootFromTerminal(zk, params, query, terminal).assertEqual(expectedRoot);
    }
}
