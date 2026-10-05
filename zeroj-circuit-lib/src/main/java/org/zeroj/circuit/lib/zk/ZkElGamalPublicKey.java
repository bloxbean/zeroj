package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkValue;
import org.zeroj.circuit.lib.jubjub.InCircuitElGamal;

import java.util.List;
import java.util.Objects;

/**
 * An {@code elgamal-jubjub-v1} encryption key inside a circuit, typed by how it entered
 * (ADR-0052 D3, invariant I8). Both constructors assert the curve equation and
 * {@code PK ≠ O}:
 * <ul>
 *   <li>{@link #fromVerifierFixedPublic}: both coordinates are declared public inputs, and
 *       subgroup membership is the <b>verifier's obligation</b>, discharged when it fixes the
 *       key. An example is a script parameter whose key shares carry proofs of possession.</li>
 *   <li>{@link #witnessInSubgroup}: the key is a prover witness, proved in the prime-order
 *       subgroup in-circuit (about 5,500 rows).</li>
 * </ul>
 */
public final class ZkElGamalPublicKey implements ZkValue {

    /** How the key entered the circuit. */
    public enum Origin {
        /** Public coordinates fixed by the verifier; subgroup membership is the verifier's job. */
        VERIFIER_FIXED_PUBLIC,
        /** Prover-supplied, proved in the prime-order subgroup in-circuit. */
        WITNESSED_IN_SUBGROUP
    }

    private final ZkField u;
    private final ZkField v;
    private final InCircuitElGamal.Key key;
    private final Origin origin;

    private ZkElGamalPublicKey(ZkField u, ZkField v, InCircuitElGamal.Key key, Origin origin) {
        this.u = u;
        this.v = v;
        this.key = key;
        this.origin = origin;
    }

    /**
     * A key whose coordinates are declared public inputs fixed by the verifier.
     *
     * @throws IllegalArgumentException if a coordinate is not a declared public input
     */
    public static ZkElGamalPublicKey fromVerifierFixedPublic(ZkContext zk, ZkField u, ZkField v) {
        requireInputs(zk, u, v);
        InCircuitElGamal.Key key = InCircuitElGamal.keyFromVerifierFixedPublic(
                zk.builder().api(), u.signal().variable(), v.signal().variable());
        return new ZkElGamalPublicKey(u, v, key, Origin.VERIFIER_FIXED_PUBLIC);
    }

    /** A prover-supplied key, proved in the prime-order subgroup and non-identity in-circuit. */
    public static ZkElGamalPublicKey witnessInSubgroup(ZkContext zk, ZkField u, ZkField v) {
        requireInputs(zk, u, v);
        InCircuitElGamal.Key key = InCircuitElGamal.keyWitnessedInSubgroup(
                zk.builder().api(), u.signal().variable(), v.signal().variable());
        return new ZkElGamalPublicKey(u, v, key, Origin.WITNESSED_IN_SUBGROUP);
    }

    /** How the key entered. */
    public Origin origin() {
        return origin;
    }

    /** Affine {@code u}. */
    public ZkField u() {
        return u;
    }

    /** Affine {@code v}. */
    public ZkField v() {
        return v;
    }

    InCircuitElGamal.Key key() {
        return key;
    }

    void requireSameContext(ZkContext zk) {
        zk.requireSignal(u.signal());
        zk.requireSignal(v.signal());
    }

    @Override
    public List<Signal> signals() {
        return List.of(u.signal(), v.signal());
    }

    /** Constraints are emitted at construction; nothing further is needed. */
    @Override
    public void assertWellFormed() {}

    private static void requireInputs(ZkContext zk, ZkField u, ZkField v) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(u, "u");
        Objects.requireNonNull(v, "v");
        zk.requireSignal(u.signal());
        zk.requireSignal(v.signal());
    }
}
