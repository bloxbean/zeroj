package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Fixed-size symbolic byte vector backed by 8-bit {@link ZkUInt} values.
 */
public final class ZkBytes implements ZkValue {
    private final List<ZkUInt> bytes;

    public ZkBytes(List<ZkUInt> bytes) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.isEmpty()) {
            throw new IllegalArgumentException("bytes must not be empty");
        }
        for (ZkUInt value : bytes) {
            if (value.bits() != 8) {
                throw new IllegalArgumentException("bytes must contain only 8-bit ZkUInt values");
            }
        }
        this.bytes = List.copyOf(bytes);
    }

    public static ZkBytes publicInput(SignalBuilder builder, String baseName, int size) {
        return bind(builder, baseName, size, ZkUInt::publicInput);
    }

    public static ZkBytes secret(SignalBuilder builder, String baseName, int size) {
        return bind(builder, baseName, size, ZkUInt::secret);
    }

    private static ZkBytes bind(SignalBuilder builder, String baseName, int size, ByteFactory factory) {
        Objects.requireNonNull(builder, "builder");
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(factory, "factory");
        if (size <= 0) {
            throw new IllegalArgumentException("size must be positive");
        }
        var values = new ArrayList<ZkUInt>(size);
        for (int i = 0; i < size; i++) {
            values.add(factory.create(builder, baseName + "_" + i, 8));
        }
        return new ZkBytes(values);
    }

    public int size() {
        return bytes.size();
    }

    public ZkUInt get(int index) {
        return bytes.get(index);
    }

    public List<ZkUInt> values() {
        return bytes;
    }

    public ZkBool isEqual(ZkBytes other) {
        requireSameSize(other);
        ZkBool result = bytes.getFirst().isEqual(other.bytes.getFirst());
        for (int i = 1; i < bytes.size(); i++) {
            result = result.and(bytes.get(i).isEqual(other.bytes.get(i)));
        }
        return result;
    }

    public void assertEqual(ZkBytes other) {
        isEqual(other).assertTrue();
    }

    @Override
    public List<Signal> signals() {
        var signals = new ArrayList<Signal>(bytes.size());
        for (ZkUInt value : bytes) {
            signals.add(value.signal());
        }
        return List.copyOf(signals);
    }

    @Override
    public void assertWellFormed() {
        for (ZkUInt value : bytes) {
            value.assertWellFormed();
        }
    }

    private void requireSameSize(ZkBytes other) {
        Objects.requireNonNull(other, "other");
        if (bytes.size() != other.bytes.size()) {
            throw new IllegalArgumentException("byte vectors must have equal length");
        }
    }

    @FunctionalInterface
    private interface ByteFactory {
        ZkUInt create(SignalBuilder builder, String name, int bits);
    }
}
