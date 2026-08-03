package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

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
