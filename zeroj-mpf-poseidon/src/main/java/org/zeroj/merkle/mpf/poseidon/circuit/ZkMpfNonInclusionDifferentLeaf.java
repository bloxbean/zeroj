package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/** MPF v1 non-inclusion primitive for a terminal authenticated conflicting leaf. */
public final class ZkMpfNonInclusionDifferentLeaf {
    private ZkMpfNonInclusionDifferentLeaf() {}

    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryPath,
            ZkArray<ZkUInt> conflictingLeafPath,
            ZkField conflictingValueCommitment,
            ZkUInt terminalSkip,
            ZkField expectedRoot,
            ZkMpfBranchProof branchProof) {
        ZkMpf.differentLeafRoot(
                zk, params, queryPath, conflictingLeafPath,
                conflictingValueCommitment, terminalSkip, branchProof)
                .assertEqual(expectedRoot);
    }
}
