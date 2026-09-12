package org.zeroj.merkle.mpf.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

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
