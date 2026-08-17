package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

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
