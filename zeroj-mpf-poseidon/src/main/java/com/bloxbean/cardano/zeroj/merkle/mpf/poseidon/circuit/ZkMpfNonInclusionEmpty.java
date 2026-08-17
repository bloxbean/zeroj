package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** MPF v1 non-inclusion primitive for an authenticated empty child. */
public final class ZkMpfNonInclusionEmpty {
    private ZkMpfNonInclusionEmpty() {}

    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> queryPath,
            ZkField expectedRoot,
            ZkMpfBranchProof proof) {
        ZkMpf.branchOnlyRoot(zk, params, queryPath, zk.constant(0), false, proof)
                .assertEqual(expectedRoot);
    }
}
