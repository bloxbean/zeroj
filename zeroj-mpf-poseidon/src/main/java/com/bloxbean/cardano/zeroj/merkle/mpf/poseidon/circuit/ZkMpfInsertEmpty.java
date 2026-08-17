package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;

/** Canonical MPF insertion into an authenticated missing branch child. */
public final class ZkMpfInsertEmpty {
    private ZkMpfInsertEmpty() {}

    public static void verify(
            ZkContext zk,
            PoseidonParams params,
            ZkArray<ZkUInt> keyPath,
            ZkField valueCommitment,
            ZkField oldRoot,
            ZkField newRoot,
            ZkMpfBranchProof oldProof) {
        ZkMpf.verifyBranchTransition(
                zk, params, keyPath, zk.constant(0), false,
                valueCommitment, true, oldRoot, newRoot, oldProof);
    }
}
