package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/**
 * Java-only namespace for the two insertion relations. There is deliberately no universal
 * insertion R1CS or witness-controlled proof-form selector.
 */
public final class ZkJmtInsert {
    private ZkJmtInsert() {}

    public static void verifyEmpty(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles,
            ZkField insertedValueHash,
            ZkField oldRoot,
            ZkField newRoot,
            ZkJmtPathProof proof) {
        ZkJmtInsertEmpty.verify(
                zk, params, keyNibbles, insertedValueHash, oldRoot, newRoot, proof);
    }

    public static void verifyDifferentLeaf(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryNibbles,
            ZkField insertedValueHash,
            ZkArray<ZkUInt> conflictingNibbles,
            ZkField conflictingValueHash,
            ZkField oldRoot,
            ZkField newRoot,
            ZkJmtPathProof proof) {
        ZkJmtInsertDifferentLeaf.verify(
                zk, params, queryNibbles, insertedValueHash,
                conflictingNibbles, conflictingValueHash, oldRoot, newRoot, proof);
    }
}
