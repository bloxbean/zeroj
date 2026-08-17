package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

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
