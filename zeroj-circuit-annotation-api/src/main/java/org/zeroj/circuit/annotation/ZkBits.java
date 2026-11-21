package org.zeroj.circuit.annotation;

import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Fixed-size symbolic bit vector backed by constrained {@link ZkBool} values.
 */
public final class ZkBits implements ZkValue {
    private final List<ZkBool> bits;

    public ZkBits(List<ZkBool> bits) {
        Objects.requireNonNull(bits, "bits");
        if (bits.isEmpty()) {
            throw new IllegalArgumentException("bits must not be empty");
        }
        Signal firstSignal = null;
        for (ZkBool bit : bits) {
            Objects.requireNonNull(bit, "bits element");
            Signal current = bit.signal();
            if (firstSignal == null) {
                firstSignal = current;
            } else if (!firstSignal.hasSameBuilder(current)) {
                throw new IllegalArgumentException("Symbolic values belong to different circuit builders");
            }
        }
        this.bits = List.copyOf(bits);
    }

    public static ZkBits publicInput(SignalBuilder builder, String baseName, int size) {
        return bind(builder, baseName, size, ZkBool::publicInput);
    }

    public static ZkBits secret(SignalBuilder builder, String baseName, int size) {
        return bind(builder, baseName, size, ZkBool::secret);
    }

    private static ZkBits bind(SignalBuilder builder, String baseName, int size, BitFactory factory) {
        Objects.requireNonNull(builder, "builder");
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(factory, "factory");
        if (size <= 0) {
            throw new IllegalArgumentException("size must be positive");
        }
        var values = new ArrayList<ZkBool>(size);
        for (int i = 0; i < size; i++) {
            values.add(factory.create(builder, baseName + "_" + i));
        }
        return new ZkBits(values);
    }

    public int size() {
        return bits.size();
    }

    public ZkBool get(int index) {
        return bits.get(index);
    }

    public List<ZkBool> values() {
        return bits;
    }

    public ZkBool isEqual(ZkBits other) {
        requireSameSize(other);
        ZkBool result = bits.getFirst().isEqual(other.bits.getFirst());
        for (int i = 1; i < bits.size(); i++) {
            result = result.and(bits.get(i).isEqual(other.bits.get(i)));
        }
        return result;
    }

    public void assertEqual(ZkBits other) {
        requireSameSize(other);
        for (int i = 0; i < bits.size(); i++) {
            bits.get(i).assertEqual(other.bits.get(i));
        }
    }

    @Override
    public List<Signal> signals() {
        var signals = new ArrayList<Signal>(bits.size());
        for (ZkBool bit : bits) {
            signals.add(bit.signal());
        }
        return List.copyOf(signals);
    }

    @Override
    public void assertWellFormed() {
        for (ZkBool bit : bits) {
            bit.assertWellFormed();
        }
    }

    private void requireSameSize(ZkBits other) {
        Objects.requireNonNull(other, "other");
        if (bits.size() != other.bits.size()) {
            throw new IllegalArgumentException("bit vectors must have equal length");
        }
    }

    @FunctionalInterface
    private interface BitFactory {
        ZkBool create(SignalBuilder builder, String name);
    }
}
