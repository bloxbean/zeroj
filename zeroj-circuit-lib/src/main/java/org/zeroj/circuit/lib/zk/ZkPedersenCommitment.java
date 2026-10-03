package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.annotation.ZkValue;

import java.util.List;
import java.util.Objects;

/**
 * A {@code pedersen-jubjub-v1} commitment inside a circuit, typed by where it came from
 * (ADR-0051 D3, invariant I4).
 *
 * <p>Every point this type holds is either computed here from the profile's bases or has had
 * its subgroup membership discharged, so homomorphic operations never silently combine an
 * unvalidated point. There are exactly three ways in:
 *
 * <ul>
 *   <li>{@link #commit} — computed in this circuit from a value and a full-width blinding
 *       (case a). The value is known to the circuit, so the commitment can take part in a
 *       {@link ZkPedersen#assertBalanced balance}. To bind a commitment someone else
 *       published, commit to its opening and call {@link #assertAffineEquals} with the
 *       published coordinates: the opening itself proves curve and subgroup membership.</li>
 *   <li>{@link #witnessInSubgroup} — an unopened commitment supplied by the prover. Bound with
 *       the curve equation and proved in the prime-order subgroup in-circuit (case b, about
 *       5,500 rows).</li>
 *   <li>{@link #fromVerifierCheckedPublic} — an unopened commitment whose coordinates are
 *       public inputs or constants (enforced by the DSL). The curve equation is asserted;
 *       subgroup membership is the <b>verifier's</b> documented obligation, checked before
 *       the proof is accepted (case c). An on-chain verifier cannot discharge it for Jubjub at
 *       practical cost, so on-chain consumers must use case a or b.</li>
 * </ul>
 *
 * <p>{@link #add} and {@link #subtract} combine commitments mod {@code l}. Their results carry
 * no known value: reading a homomorphic relation as integer conservation requires the bounds
 * in {@link ZkPedersen#assertBalanced} (I6).
 *
 * <p><b>Public-input encoding (D4).</b> A commitment is exposed to a verifier as two public
 * inputs, affine {@code u} then {@code v}, bound with {@link #assertAffineEquals}.
 */
public final class ZkPedersenCommitment implements ZkValue {

    /** Where a commitment came from. Determines what the circuit knows about it. */
    public enum Origin {
        /** Computed here from a known value and blinding (case a). */
        COMPUTED,
        /** Prover-supplied, curve-bound and subgroup-checked in-circuit (case b). */
        WITNESSED_IN_SUBGROUP,
        /** Public or constant coordinates; subgroup membership is the verifier's job (case c). */
        VERIFIER_CHECKED_PUBLIC,
        /** The sum or difference of other commitments. */
        COMBINED
    }

    private final ZkContext context;
    private final ZkJubjubPoint point;
    private final ZkUInt value;
    private final Origin origin;

    private ZkPedersenCommitment(ZkContext context, ZkJubjubPoint point, ZkUInt value, Origin origin) {
        this.context = Objects.requireNonNull(context, "context");
        this.point = Objects.requireNonNull(point, "point");
        this.value = value;
        this.origin = Objects.requireNonNull(origin, "origin");
    }

    /**
     * Commits to {@code value} with a full-width {@code blinding}, with every rule of
     * {@link ZkPedersen#commit(ZkContext, ZkUInt, ZkUInt)} (case a).
     */
    public static ZkPedersenCommitment commit(ZkContext zk, ZkUInt value, ZkUInt blinding) {
        ZkJubjubPoint point = ZkPedersen.commit(zk, value, blinding);
        return new ZkPedersenCommitment(zk, point, value, Origin.COMPUTED);
    }

    /**
     * Binds an unopened, prover-supplied commitment: asserts the curve equation and proves
     * prime-order subgroup membership in-circuit (case b).
     */
    public static ZkPedersenCommitment witnessInSubgroup(ZkContext zk, ZkField u, ZkField v) {
        ZkJubjubPoint point = ZkJubjubPoint.witnessAffine(zk, u, v);
        point.assertInPrimeOrderSubgroup(zk);
        return new ZkPedersenCommitment(zk, point, null, Origin.WITNESSED_IN_SUBGROUP);
    }

    /**
     * Binds an unopened commitment whose coordinates the verifier sees (case c). Both
     * coordinates must be public inputs or circuit constants — a secret or derived wire is
     * rejected at circuit-definition time — and the curve equation is asserted.
     *
     * <p><b>Subgroup membership is not proved here.</b> The verifier must decode the public
     * commitment with {@code PedersenCommitment.decode} (or an equivalent subgroup check)
     * before accepting the proof. On-chain consumers cannot, and must use
     * {@link #witnessInSubgroup} or {@link #commit} instead.
     */
    public static ZkPedersenCommitment fromVerifierCheckedPublic(ZkContext zk, ZkField u, ZkField v) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(u, "u");
        Objects.requireNonNull(v, "v");
        zk.requireSignal(u.signal());
        zk.requireSignal(v.signal());
        var api = zk.builder().api();
        api.requirePublicOrConstant(u.signal().variable());
        api.requirePublicOrConstant(v.signal().variable());
        ZkJubjubPoint point = ZkJubjubPoint.witnessAffine(zk, u, v);
        return new ZkPedersenCommitment(zk, point, null, Origin.VERIFIER_CHECKED_PUBLIC);
    }

    /** {@code this + other}, mod {@code l}. The result's value is not known to the circuit. */
    public ZkPedersenCommitment add(ZkContext zk, ZkPedersenCommitment other) {
        Objects.requireNonNull(other, "other");
        requireSameContext(zk);
        other.requireSameContext(zk);
        return new ZkPedersenCommitment(zk, point.add(zk, other.point), null, Origin.COMBINED);
    }

    /** {@code this − other}, mod {@code l}. The result's value is not known to the circuit. */
    public ZkPedersenCommitment subtract(ZkContext zk, ZkPedersenCommitment other) {
        Objects.requireNonNull(other, "other");
        requireSameContext(zk);
        other.requireSameContext(zk);
        return new ZkPedersenCommitment(zk, point.subtract(zk, other.point), null, Origin.COMBINED);
    }

    /** Asserts this commitment equals the affine point {@code (u, v)} — the D4 encoding. */
    public void assertAffineEquals(ZkContext zk, ZkField u, ZkField v) {
        requireSameContext(zk);
        point.assertAffineEquals(zk, u, v);
    }

    /** Asserts this commitment equals {@code other} as a point. */
    public void assertEqual(ZkContext zk, ZkPedersenCommitment other) {
        Objects.requireNonNull(other, "other");
        requireSameContext(zk);
        other.requireSameContext(zk);
        point.assertEqual(zk, other.point);
    }

    public ZkJubjubPoint point() {
        return point;
    }

    public Origin origin() {
        return origin;
    }

    /** Whether the committed value is known to this circuit (only for {@link Origin#COMPUTED}). */
    public boolean hasKnownValue() {
        return value != null;
    }

    /** The committed value, or {@code null} when it is not known to this circuit. */
    ZkUInt knownValue() {
        return value;
    }

    @Override
    public List<Signal> signals() {
        return point.signals();
    }

    @Override
    public void assertWellFormed() {
        point.assertWellFormed();
    }

    void requireSameContext(ZkContext zk) {
        Objects.requireNonNull(zk, "zk");
        if (zk.builder() != context.builder()) {
            throw new IllegalArgumentException("Pedersen commitment belongs to a different circuit builder");
        }
        point.requireSameContext(zk);
    }
}
