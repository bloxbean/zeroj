package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
