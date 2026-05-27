package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMiMC;

import java.util.Objects;

/**
 * Symbolic MiMC adapter for annotation-based circuits.
 */
public final class ZkMiMC {

    private ZkMiMC() {}

    public static ZkField hash(ZkContext zk, ZkField left, ZkField right) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(left, "left");
        Objects.requireNonNull(right, "right");
        zk.requireSignal(left.signal());
        zk.requireSignal(right.signal());

        return ZkField.wrap(zk, SignalMiMC.hash(zk.builder(), left.signal(), right.signal()));
    }
}
