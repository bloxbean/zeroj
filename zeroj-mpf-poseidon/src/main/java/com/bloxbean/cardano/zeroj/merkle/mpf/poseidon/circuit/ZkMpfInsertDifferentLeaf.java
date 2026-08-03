package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/**
 * Canonical MPF v1 insertion that splits an authenticated conflicting leaf at
 * the first divergent key nibble.
 */
public final class ZkMpfInsertDifferentLeaf {
    private ZkMpfInsertDifferentLeaf() {}

    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryPath,
            ZkField insertedValueCommitment,
            ZkArray<ZkUInt> conflictingLeafPath,
            ZkField conflictingValueCommitment,
            ZkUInt terminalSkip,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof branchProof) {
        ZkMpf.verifyDifferentLeafInsertion(
                zk, params, queryPath, insertedValueCommitment,
                conflictingLeafPath, conflictingValueCommitment, terminalSkip,
                oldRoot, newRoot, branchProof);
    }
}
