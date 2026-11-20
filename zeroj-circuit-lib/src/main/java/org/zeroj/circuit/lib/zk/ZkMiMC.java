package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.SignalMiMC;
import org.zeroj.circuit.lib.poseidon.PoseidonParams;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.util.Objects;

/**
 * <b>DEPRECATED FOR REMOVAL — INSECURE / INVERTIBLE — DO NOT USE.</b>
 *
 * <p>Delegates to {@link SignalMiMC#hash}, which computes an invertible keyed bijection without
 * feed-forward on BN254. Preimages and Merkle membership proofs are trivially forgeable.
 * Use {@link ZkPoseidon#hash(ZkContext, PoseidonParams, ZkField, ZkField)} with
 * {@link PoseidonParamsBLS12_381T3#INSTANCE} on BLS12-381 instead.</p>
 *
 * @deprecated Scheduled for removal. Use
 *             {@link ZkPoseidon#hash(ZkContext, PoseidonParams, ZkField, ZkField)} with
 *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
 */
@Deprecated(forRemoval = true)
@SuppressWarnings("removal")
public final class ZkMiMC {

    private ZkMiMC() {}

    /**
     * @deprecated Scheduled for removal. Use
     *             {@link ZkPoseidon#hash(ZkContext, PoseidonParams, ZkField, ZkField)} with
     *             {@link PoseidonParamsBLS12_381T3#INSTANCE} instead.
     */
    @Deprecated(forRemoval = true)
    public static ZkField hash(ZkContext zk, ZkField left, ZkField right) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(left, "left");
        Objects.requireNonNull(right, "right");
        zk.requireSignal(left.signal());
        zk.requireSignal(right.signal());

        return ZkField.wrap(zk, SignalMiMC.hash(zk.builder(), left.signal(), right.signal()));
    }
}
