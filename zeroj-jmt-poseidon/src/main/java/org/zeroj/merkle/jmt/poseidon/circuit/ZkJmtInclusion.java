package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
