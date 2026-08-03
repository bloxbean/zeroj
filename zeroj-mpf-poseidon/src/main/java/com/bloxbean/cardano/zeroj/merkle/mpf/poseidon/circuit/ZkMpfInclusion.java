package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Operation-specific MPF v1 inclusion primitive. */
public final class ZkMpfInclusion {
    private ZkMpfInclusion() {}

    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField expectedRoot,
            ZkMpfBranchProof proof) {
        ZkMpf.branchOnlyRoot(zk, params, keyPath, valueCommitment, true, proof)
                .assertEqual(expectedRoot);
    }

    /**
     * Verifies every MPF v1 inclusion proof form supported by the strict CCL
     * normalizer. Prefer the branch-only overload when normalization proves
     * that all steps are BranchSteps; it has a materially smaller R1CS.
     */
    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField expectedRoot,
            ZkMpfProof proof) {
        ZkMpf.verifyInclusionPoseidon(
                zk, params, keyPath, valueCommitment, expectedRoot, proof);
    }
}
