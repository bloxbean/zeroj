package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Java dispatch facade for the two fixed MPF insertion proof languages. */
public final class ZkMpfInsert {
    private ZkMpfInsert() {}

    public static void verifyEmpty(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof proof) {
        ZkMpfInsertEmpty.verify(
                zk, params, keyPath, valueCommitment, oldRoot, newRoot, proof);
    }

    public static void verifyDifferentLeaf(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryPath,
            ZkField insertedValueCommitment,
            ZkArray<ZkUInt> conflictingLeafPath,
            ZkField conflictingValueCommitment,
            ZkUInt terminalSkip,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof proof) {
        ZkMpfInsertDifferentLeaf.verify(
                zk, params, queryPath, insertedValueCommitment,
                conflictingLeafPath, conflictingValueCommitment, terminalSkip,
                oldRoot, newRoot, proof);
    }
}
