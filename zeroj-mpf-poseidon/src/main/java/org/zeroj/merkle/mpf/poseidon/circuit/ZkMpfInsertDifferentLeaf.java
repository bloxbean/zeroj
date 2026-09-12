package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
