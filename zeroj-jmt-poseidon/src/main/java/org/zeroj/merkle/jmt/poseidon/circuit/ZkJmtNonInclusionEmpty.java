package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
