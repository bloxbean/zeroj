package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkValue;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.util.List;
import java.util.Objects;

/**
 * Symbolic Jubjub point backed by extended-coordinate field values.
 *
 * <p>This adapter is intentionally a thin wrapper over {@link InCircuitJubjub}.
 * It does not add curve or subgroup checks for arbitrary witness points; callers
 * should only bind points that were validated off-circuit or produced by a
 * reviewed gadget.
 */
public final class ZkJubjubPoint implements ZkValue {
    private final ZkField u;
    private final ZkField v;
    private final ZkField z;
    private final ZkField t;

    private ZkJubjubPoint(ZkField u, ZkField v, ZkField z, ZkField t) {
        this.u = Objects.requireNonNull(u, "u");
        this.v = Objects.requireNonNull(v, "v");
        this.z = Objects.requireNonNull(z, "z");
        this.t = Objects.requireNonNull(t, "t");
    }

    /**
     * Binds an affine point whose curve validity, subgroup membership, and
     * identity policy were checked off-circuit before the values entered the
     * circuit.
     */
    public static ZkJubjubPoint fromTrustedAffine(ZkContext zk, ZkField u, ZkField v) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(u, "u");
        Objects.requireNonNull(v, "v");
        requireBls12381(zk);
        zk.requireSignal(u.signal());
        zk.requireSignal(v.signal());
        return new ZkJubjubPoint(
                u,
                v,
                ZkField.wrap(zk, zk.builder().constant(1)),
                u.mul(v));
    }

    public static ZkJubjubPoint constant(ZkContext zk, JubjubPoint point) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(point, "point");
        return wrap(zk, InCircuitJubjub.constant(zk.builder().api(), point));
    }

    static ZkJubjubPoint wrap(ZkContext zk, InCircuitJubjub.Point point) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(point, "point");
        requireBls12381(zk);
        return new ZkJubjubPoint(
                ZkField.wrap(zk, zk.builder().wrap(point.u())),
                ZkField.wrap(zk, zk.builder().wrap(point.v())),
                ZkField.wrap(zk, zk.builder().wrap(point.z())),
                ZkField.wrap(zk, zk.builder().wrap(point.t())));
    }

    public ZkField u() {
        return u;
    }

    public ZkField v() {
        return v;
    }

    public ZkField z() {
        return z;
    }

    public ZkField t() {
        return t;
    }

    public ZkJubjubPoint add(ZkContext zk, ZkJubjubPoint other) {
        requireSameContext(zk);
        other.requireSameContext(zk);
        requireBls12381(zk);
        return wrap(zk, InCircuitJubjub.add(zk.builder().api(), asPoint(), other.asPoint()));
    }

    public ZkJubjubPoint doubled(ZkContext zk) {
        requireSameContext(zk);
        requireBls12381(zk);
        return wrap(zk, InCircuitJubjub.doubled(zk.builder().api(), asPoint()));
    }

    public static ZkJubjubPoint select(
            ZkContext zk,
            ZkBool condition,
            ZkJubjubPoint ifTrue,
            ZkJubjubPoint ifFalse) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(condition, "condition");
        Objects.requireNonNull(ifTrue, "ifTrue");
        Objects.requireNonNull(ifFalse, "ifFalse");
        ifTrue.requireSameContext(zk);
        ifFalse.requireSameContext(zk);
        zk.requireSignal(condition.signal());
        requireBls12381(zk);
        return wrap(zk, InCircuitJubjub.select(
                zk.builder().api(), condition.signal().variable(), ifTrue.asPoint(), ifFalse.asPoint()));
    }

    public void assertEqual(ZkContext zk, ZkJubjubPoint other) {
        requireSameContext(zk);
        other.requireSameContext(zk);
        requireBls12381(zk);
        var api = zk.builder().api();
        api.assertEqual(api.mul(u.signal().variable(), other.z.signal().variable()),
                api.mul(other.u.signal().variable(), z.signal().variable()));
        api.assertEqual(api.mul(v.signal().variable(), other.z.signal().variable()),
                api.mul(other.v.signal().variable(), z.signal().variable()));
    }

    public ZkBool isEqual(ZkContext zk, ZkJubjubPoint other) {
        requireSameContext(zk);
        other.requireSameContext(zk);
        requireBls12381(zk);
        var api = zk.builder().api();
        var sameU = api.isEqual(
                api.mul(u.signal().variable(), other.z.signal().variable()),
                api.mul(other.u.signal().variable(), z.signal().variable()));
        var sameV = api.isEqual(
                api.mul(v.signal().variable(), other.z.signal().variable()),
                api.mul(other.v.signal().variable(), z.signal().variable()));
        return ZkBool.wrap(zk, zk.builder().wrap(api.and(sameU, sameV)));
    }

    public ZkBool isIdentity(ZkContext zk) {
        requireSameContext(zk);
        requireBls12381(zk);
        var api = zk.builder().api();
        return ZkBool.wrap(zk, zk.builder().wrap(api.and(
                api.isZero(u.signal().variable()),
                api.isEqual(v.signal().variable(), z.signal().variable()))));
    }

    public void assertNotIdentity(ZkContext zk) {
        isIdentity(zk).assertFalse();
    }

    public void assertAffineEquals(ZkContext zk, ZkField affineU, ZkField affineV) {
        Objects.requireNonNull(affineU, "affineU");
        Objects.requireNonNull(affineV, "affineV");
        requireSameContext(zk);
        zk.requireSignal(affineU.signal());
        zk.requireSignal(affineV.signal());
        requireBls12381(zk);
        var api = zk.builder().api();
        api.assertEqual(api.mul(affineU.signal().variable(), z.signal().variable()), u.signal().variable());
        api.assertEqual(api.mul(affineV.signal().variable(), z.signal().variable()), v.signal().variable());
    }

    @Override
    public List<Signal> signals() {
        return List.of(u.signal(), v.signal(), z.signal(), t.signal());
    }

    @Override
    public void assertWellFormed() {
        u.assertWellFormed();
        v.assertWellFormed();
        z.assertWellFormed();
        t.assertWellFormed();
    }

    InCircuitJubjub.Point asPoint() {
        return new InCircuitJubjub.Point(
                u.signal().variable(),
                v.signal().variable(),
                z.signal().variable(),
                t.signal().variable());
    }

    void requireSameContext(ZkContext zk) {
        Objects.requireNonNull(zk, "zk");
        zk.requireSignal(u.signal());
        zk.requireSignal(v.signal());
        zk.requireSignal(z.signal());
        zk.requireSignal(t.signal());
    }

    private static void requireBls12381(ZkContext zk) {
        zk.builder().api().requireField(PoseidonParamsBLS12_381T3.INSTANCE.field());
    }
}
