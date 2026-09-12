package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Proves that exactly one existing MPF v1 leaf value changes on one shared path. */
public final class ZkMpfValueUpdate {
    private ZkMpfValueUpdate() {}

    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField oldValueCommitment,
            ZkField newValueCommitment,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof proof) {
        oldValueCommitment.isEqual(newValueCommitment).assertFalse();
        ZkMpf.verifyBranchTransition(
                zk, params, keyPath, oldValueCommitment, true,
                newValueCommitment, true, oldRoot, newRoot, proof);
    }
}
