package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

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
