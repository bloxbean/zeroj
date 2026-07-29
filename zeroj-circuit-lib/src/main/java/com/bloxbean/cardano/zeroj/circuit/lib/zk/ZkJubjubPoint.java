package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkValue;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.InCircuitJubjub;
import com.bloxbean.cardano.zeroj.circuit.lib.jubjub.JubjubPoint;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Symbolic Jubjub point backed by extended-coordinate field values.
 *
 * <p>Every point that enters a circuit through this type is <b>constrained to be a curve
 * point</b> (ADR-0038 Decision 2). The complete inventory of ways one comes into existence —
 * worth stating exhaustively, because auditing this class against an incomplete inventory is
 * how the missing curve check survived three review passes:
 *
 * <ul>
 *   <li>{@link #witnessAffine(ZkContext, ZkField, ZkField)} — the binder for prover-supplied
 *       points. Delegates to
 *       {@link InCircuitJubjub#witnessAffine(com.bloxbean.cardano.zeroj.circuit.CircuitAPI,
 *       com.bloxbean.cardano.zeroj.circuit.Variable, com.bloxbean.cardano.zeroj.circuit.Variable)},
 *       which asserts the affine curve equation and pins {@code z = 1}, {@code t = u·v}.
 *       Because {@code z} is the constant-1 wire, the coordinates <em>are</em> affine, so a
 *       downstream hash over them cannot be ground by rescaling. Marked well-formed.</li>
 *   <li>{@link #fromTrustedAffine} — deprecated alias, delegates to the above.</li>
 *   <li>{@link #constant(ZkContext, JubjubPoint)} — a compile-time point, already validated
 *       on-curve by {@link JubjubPoint} itself. Marked well-formed.</li>
 *   <li>The arithmetic here — {@link #add}, {@link #doubled}, {@link #select} — and the
 *       <b>public</b> {@code ZkPedersen.commit}/{@code commitBits}, all of which go through
 *       the package-private {@code wrap}. These are projective results, well-formed by
 *       construction given well-formed inputs, and are <em>not</em> marked: calling
 *       {@link #assertWellFormed()} on one emits the projective invariants
 *       ({@code V² − U² == Z² + d·T²}, {@code T·Z == U·V}, {@code Z != 0}) once.</li>
 * </ul>
 *
 * <p>Repeated {@link #assertWellFormed()} calls are free.
 *
 * <h2>Projective predicates fail closed</h2>
 * The projective comparison helpers — {@link #assertEqual}, {@link #isEqual},
 * {@link #assertAffineEquals}, and {@link #isIdentity} — first establish {@code Z != 0}
 * locally and idempotently. Without that guard an all-zero operand would make every
 * cross-product read {@code 0 == 0}. The construction inventory above is still deliberately
 * closed, but predicate soundness no longer rests on that inventory alone.
 *
 * <h2>What this type does not establish</h2>
 * Prime-order subgroup membership. That is a separate and much more expensive check — a full
 * {@code [l]·P} multiplication — applied only where the threat model needs it; see
 * {@code InCircuitEdDSAJubjub.verifyStrict}.
 *
 * <h2>Withdrawn model</h2>
 * Before ADR-0038 this type emitted <b>no point constraints at all</b>:
 * {@code fromTrustedAffine} pinned {@code z} and {@code t} without asserting the curve
 * equation, {@code assertWellFormed()} checked four ordinary field elements, and the Javadoc
 * told callers to "only bind points that were validated off-circuit". An off-curve
 * {@code (u, v) = (1, 1)} was accepted. That is the
 * validate-off-circuit-then-trust-in-circuit model ADR-0037 Decision 1 removed: the caller
 * never sees the prover's witness, so no off-circuit check constrains it.
 * {@link #fromTrustedAffine} survives only as a deprecated alias that now binds safely.
 */
public final class ZkJubjubPoint implements ZkValue {
    /**
     * Retained so {@link #assertWellFormed()} — which takes no {@link ZkContext}, because
     * {@link ZkValue} does not give it one — can emit constraints into the circuit this point
     * belongs to.
     */
    private final ZkContext context;

    private final ZkField u;
    private final ZkField v;
    private final ZkField z;
    private final ZkField t;

    /**
     * Whether this point's well-formedness is already established, either eagerly by the
     * affine binder or by a previous {@link #assertWellFormed()} call. Makes the assertion
     * idempotent, so a point asserted twice does not pay twice.
     */
    private boolean wellFormed;
    /** Whether this object has already emitted or inherited the local {@code Z != 0} guard. */
    private boolean nonZeroZEstablished;

    private ZkJubjubPoint(ZkContext context, ZkField u, ZkField v, ZkField z, ZkField t,
                          boolean wellFormed) {
        this.context = Objects.requireNonNull(context, "context");
        this.u = Objects.requireNonNull(u, "u");
        this.v = Objects.requireNonNull(v, "v");
        this.z = Objects.requireNonNull(z, "z");
        this.t = Objects.requireNonNull(t, "t");
        this.wellFormed = wellFormed;
        this.nonZeroZEstablished = wellFormed;
    }

    /**
     * Binds a prover-supplied point given by its <b>affine</b> coordinates, emitting every
     * constraint needed to make it a usable curve point: the affine curve equation
     * {@code v² − u² == 1 + d·u²·v²}, {@code z = 1} (so {@code z != 0} holds by construction
     * and the representation is canonical), and {@code t == u·v}.
     *
     * <p>This is the supported way to bring an untrusted point into a circuit. Cost: 5
     * constraints. It does <b>not</b> establish prime-order subgroup membership.
     *
     * @throws IllegalArgumentException if either coordinate belongs to a different builder
     */
    public static ZkJubjubPoint witnessAffine(ZkContext zk, ZkField u, ZkField v) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(u, "u");
        Objects.requireNonNull(v, "v");
        requireBls12381(zk);
        zk.requireSignal(u.signal());
        zk.requireSignal(v.signal());
        // The gadget asserts the curve equation and returns (u, v, 1, u·v).
        InCircuitJubjub.Point bound = InCircuitJubjub.witnessAffine(
                zk.builder().api(), u.signal().variable(), v.signal().variable());
        return wrap(zk, bound, true);
    }

    /**
     * @deprecated The name describes the model ADR-0037 Decision 1 removed: there is no such
     *         thing as an affine point a circuit may trust, because the caller never sees the
     *         prover's witness. This now delegates to
     *         {@link #witnessAffine(ZkContext, ZkField, ZkField)} and therefore <b>does</b>
     *         assert the curve equation — the historical behaviour, which asserted nothing and
     *         accepted an off-curve {@code (1, 1)}, is gone. Use {@code witnessAffine}.
     */
    @Deprecated(since = "ADR-0038")
    public static ZkJubjubPoint fromTrustedAffine(ZkContext zk, ZkField u, ZkField v) {
        return witnessAffine(zk, u, v);
    }

    /**
     * Wraps a compile-time point as circuit constants. The point was validated on-curve when
     * the {@link JubjubPoint} was constructed, so no constraints are needed.
     */
    public static ZkJubjubPoint constant(ZkContext zk, JubjubPoint point) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(point, "point");
        return wrap(zk, InCircuitJubjub.constant(zk.builder().api(), point), true);
    }

    /**
     * Wraps a gadget-internal projective result. Not marked well-formed: the invariants hold
     * by construction given well-formed inputs, but {@link #assertWellFormed()} will still
     * emit them on request, which is the conservative direction.
     */
    static ZkJubjubPoint wrap(ZkContext zk, InCircuitJubjub.Point point) {
        return wrap(zk, point, false);
    }

    private static ZkJubjubPoint wrap(ZkContext zk, InCircuitJubjub.Point point,
                                      boolean wellFormed) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(point, "point");
        requireBls12381(zk);
        return new ZkJubjubPoint(
                zk,
                ZkField.wrap(zk, zk.builder().wrap(point.u())),
                ZkField.wrap(zk, zk.builder().wrap(point.v())),
                ZkField.wrap(zk, zk.builder().wrap(point.z())),
                ZkField.wrap(zk, zk.builder().wrap(point.t())),
                wellFormed);
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
        assertNonZeroZ();
        other.assertNonZeroZ();
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
        assertNonZeroZ();
        other.assertNonZeroZ();
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
        assertNonZeroZ();
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
        assertNonZeroZ();
        var api = zk.builder().api();
        api.assertEqual(api.mul(affineU.signal().variable(), z.signal().variable()), u.signal().variable());
        api.assertEqual(api.mul(affineV.signal().variable(), z.signal().variable()), v.signal().variable());
    }

    @Override
    public List<Signal> signals() {
        return List.of(u.signal(), v.signal(), z.signal(), t.signal());
    }

    /**
     * Asserts that this point is a well-formed projective curve point:
     * {@code V² − U² == Z² + d·T²}, {@code T·Z == U·V}, and {@code Z != 0}.
     *
     * <p>All three conjuncts are required. The all-zero point {@code (0,0,0,0)} satisfies the
     * first two identically — each reduces to {@code 0 == 0} — propagates through the addition
     * formula to an all-zero sum, and makes any projective-equality assertion read
     * {@code 0 == 0}, which is vacuously true. {@code Z != 0} is what excludes it.
     *
     * <p><b>Idempotent.</b> A point bound by {@link #witnessAffine} or minted by
     * {@link #constant} is already established and this call is free; otherwise the invariants
     * are emitted once and the point is marked thereafter, so asserting twice does not
     * constrain twice.
     *
     * <p>This deliberately accepts any nonzero rescaling {@code (λU, λV, λZ, λT)} of a valid
     * point — those are legitimate representations of the same point. It is therefore
     * <b>not sufficient at a hashing boundary</b>, where the representation itself must be
     * canonical; use {@link #witnessAffine} there, which pins {@code Z = 1}.
     *
     * <p>Before ADR-0038 this method called {@code assertWellFormed()} on its four
     * coordinates, each of which is an empty method on {@link ZkField} — every field element
     * is trivially a well-formed field element — so it emitted nothing whatsoever.
     */
    @Override
    public void assertWellFormed() {
        if (wellFormed) return;
        InCircuitJubjub.assertWellFormed(context.builder().api(), asPoint());
        wellFormed = true;
        nonZeroZEstablished = true;
    }

    /**
     * Local defence at every projective comparison/predicate boundary. Construction is intended
     * to keep malformed points unreachable, but without this check an accidentally introduced
     * all-zero wrapper makes cross-products and the identity predicate vacuously true.
     */
    private void assertNonZeroZ() {
        if (nonZeroZEstablished) return;
        var api = context.builder().api();
        api.assertNotEqual(z.signal().variable(), api.constant(BigInteger.ZERO));
        nonZeroZEstablished = true;
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
