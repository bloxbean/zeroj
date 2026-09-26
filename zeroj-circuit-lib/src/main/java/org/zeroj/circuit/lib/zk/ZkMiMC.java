package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.SignalMiMC;

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
