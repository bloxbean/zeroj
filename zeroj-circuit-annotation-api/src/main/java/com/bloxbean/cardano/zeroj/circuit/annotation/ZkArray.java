package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Fixed-size symbolic array.
 */
public final class ZkArray<T extends ZkValue> implements ZkValue {
    private final List<T> values;

    public ZkArray(List<T> values) {
        Objects.requireNonNull(values, "values");
        this.values = List.copyOf(values);
    }

    public static ZkArray<ZkField> publicFields(SignalBuilder builder, String baseName, int size) {
        return bindElements(builder, baseName, size, ZkField::publicInput);
    }

    public static ZkArray<ZkField> secretFields(SignalBuilder builder, String baseName, int size) {
        return bindElements(builder, baseName, size, ZkField::secret);
    }

    public static ZkArray<ZkBool> publicBools(SignalBuilder builder, String baseName, int size) {
        return bindElements(builder, baseName, size, ZkBool::publicInput);
    }

    public static ZkArray<ZkBool> secretBools(SignalBuilder builder, String baseName, int size) {
        return bindElements(builder, baseName, size, ZkBool::secret);
    }

    public static ZkArray<ZkUInt> publicUInts(SignalBuilder builder, String baseName, int size, int bits) {
        return bindElements(builder, baseName, size, (c, name) -> ZkUInt.publicInput(c, name, bits));
    }

    public static ZkArray<ZkUInt> secretUInts(SignalBuilder builder, String baseName, int size, int bits) {
        return bindElements(builder, baseName, size, (c, name) -> ZkUInt.secret(c, name, bits));
    }

    /**
     * Bind a custom fixed-size array. Visibility comes from the supplied
     * factory; use the visibility-specific helpers for built-in symbolic types.
     */
    public static <T extends ZkValue> ZkArray<T> bind(
            SignalBuilder builder, String baseName, int size, ElementFactory<T> factory) {
        return bindElements(builder, baseName, size, factory);
    }

    private static <T extends ZkValue> ZkArray<T> bindElements(
            SignalBuilder builder, String baseName, int size, ElementFactory<T> factory) {
        Objects.requireNonNull(builder, "builder");
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(factory, "factory");
        if (size < 0) {
            throw new IllegalArgumentException("size must be >= 0, got " + size);
        }
        var values = new ArrayList<T>(size);
        for (int i = 0; i < size; i++) {
            values.add(factory.create(builder, baseName + "_" + i));
        }
        return new ZkArray<>(values);
    }

    public int size() {
        return values.size();
    }

    public T get(int index) {
        return values.get(index);
    }

    public List<T> values() {
        return values;
    }

    @Override
    public List<Signal> signals() {
        var signals = new ArrayList<Signal>();
        for (T value : values) {
            signals.addAll(value.signals());
        }
        return List.copyOf(signals);
    }

    @Override
    public void assertWellFormed() {
        for (T value : values) {
            value.assertWellFormed();
        }
    }

    @FunctionalInterface
    public interface ElementFactory<T extends ZkValue> {
        T create(SignalBuilder builder, String name);
    }
}
