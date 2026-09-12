package org.zeroj.merkle.jmt.poseidon.circuit;

import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;

/**
 * Replaces a live value with an application-bound, public tombstone commitment.
 * The tombstone remains an included value; this is not physical deletion or non-inclusion.
 */
public final class ZkJmtTombstoneUpdate {
    private ZkJmtTombstoneUpdate() {}

    public static void verify(
            ZkContext zk, PoseidonParams params,
            ZkArray<ZkUInt> keyNibbles,
            ZkField liveValueHash, ZkField tombstoneValueHash,
            ZkField oldRoot, ZkField newRoot,
            ZkJmtPathProof proof) {
        ZkJmtValueUpdate.verify(zk, params, keyNibbles,
                liveValueHash, tombstoneValueHash, oldRoot, newRoot, proof);
    }
}
