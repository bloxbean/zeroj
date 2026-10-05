package org.zeroj.circuit.lib.zk;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.annotation.ZkValue;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;

import java.util.List;
import java.util.Objects;

/**
 * A {@code pedersen-jubjub-vector-v1} commitment inside a circuit, tied to the
 * {@link ZkPedersenVector.SchemaBinding} it was created or bound under.
 *
 * <p>{@link #add} and {@link #subtract} require the same binding object: homomorphism is defined
 * only within one schema (spec §7). Their results carry no known values. To read a component as
 * integer conservation, put the known values of computed commitments into
 * {@link ZkPedersen#assertBalanced} with {@link ZkPedersen.Term#amount}.
 */
public final class ZkPedersenVectorCommitment implements ZkValue {

    private final ZkPedersenVector.SchemaBinding binding;
    private final ZkJubjubPoint point;
    private final List<ZkUInt> values;
    private final ZkPedersenCommitment.Origin origin;

    ZkPedersenVectorCommitment(ZkPedersenVector.SchemaBinding binding, ZkJubjubPoint point,
                               List<ZkUInt> values, ZkPedersenCommitment.Origin origin) {
        this.binding = Objects.requireNonNull(binding, "binding");
        this.point = Objects.requireNonNull(point, "point");
        this.values = values;
        this.origin = Objects.requireNonNull(origin, "origin");
    }

    public PedersenVectorSchema schema() {
        return binding.schema();
    }

    public ZkPedersenCommitment.Origin origin() {
        return origin;
    }

    public boolean hasKnownValues() {
        return values != null;
    }

    /** The committed value at {@code index}; only for commitments computed in this circuit. */
    public ZkUInt value(int index) {
        if (values == null) {
            throw new IllegalStateException("a " + origin + " vector commitment has no values known to this circuit");
        }
        return values.get(index);
    }

    public ZkJubjubPoint point() {
        return point;
    }

    /** {@code this + other} under the same schema binding. */
    public ZkPedersenVectorCommitment add(ZkContext zk, ZkPedersenVectorCommitment other) {
        requireCompatible(zk, other);
        return new ZkPedersenVectorCommitment(binding, point.add(zk, other.point), null,
                ZkPedersenCommitment.Origin.COMBINED);
    }

    /** {@code this − other} under the same schema binding. */
    public ZkPedersenVectorCommitment subtract(ZkContext zk, ZkPedersenVectorCommitment other) {
        requireCompatible(zk, other);
        return new ZkPedersenVectorCommitment(binding, point.subtract(zk, other.point), null,
                ZkPedersenCommitment.Origin.COMBINED);
    }

    /** Exposes this commitment as the affine public inputs {@code (u, v)} (ADR-0051 D4). */
    public void assertAffineEquals(ZkContext zk, ZkField u, ZkField v) {
        binding.requireSameContext(zk);
        point.assertAffineEquals(zk, u, v);
    }

    public void assertEqual(ZkContext zk, ZkPedersenVectorCommitment other) {
        requireCompatible(zk, other);
        point.assertEqual(zk, other.point);
    }

    @Override
    public List<Signal> signals() {
        return point.signals();
    }

    @Override
    public void assertWellFormed() {
        point.assertWellFormed();
    }

    private void requireCompatible(ZkContext zk, ZkPedersenVectorCommitment other) {
        Objects.requireNonNull(other, "other");
        binding.requireSameContext(zk);
        if (other.binding != binding) {
            throw new IllegalArgumentException("vector commitments under different schema bindings cannot be "
                    + "combined (spec §7): " + binding.schema() + " vs " + other.binding.schema());
        }
    }
}
