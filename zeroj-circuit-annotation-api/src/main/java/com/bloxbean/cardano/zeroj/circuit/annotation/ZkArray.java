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

    public static ZkArray<ZkArray<ZkField>> publicFieldMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize) {
        return bindMatrix(builder, baseName, outerSize, innerSize, ZkArray::publicFields);
    }

    public static ZkArray<ZkArray<ZkField>> secretFieldMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize) {
        return bindMatrix(builder, baseName, outerSize, innerSize, ZkArray::secretFields);
    }

    public static ZkArray<ZkArray<ZkBool>> publicBoolMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize) {
        return bindMatrix(builder, baseName, outerSize, innerSize, ZkArray::publicBools);
    }

    public static ZkArray<ZkArray<ZkBool>> secretBoolMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize) {
        return bindMatrix(builder, baseName, outerSize, innerSize, ZkArray::secretBools);
    }

    public static ZkArray<ZkArray<ZkUInt>> publicUIntMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize, int bits) {
        return bindMatrix(builder, baseName, outerSize, innerSize,
                (c, name, size) -> ZkArray.publicUInts(c, name, size, bits));
    }

    public static ZkArray<ZkArray<ZkUInt>> secretUIntMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize, int bits) {
        return bindMatrix(builder, baseName, outerSize, innerSize,
                (c, name, size) -> ZkArray.secretUInts(c, name, size, bits));
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

    private static <T extends ZkValue> ZkArray<ZkArray<T>> bindMatrix(
            SignalBuilder builder, String baseName, int outerSize, int innerSize, MatrixRowFactory<T> factory) {
        Objects.requireNonNull(builder, "builder");
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(factory, "factory");
        if (outerSize < 0) {
            throw new IllegalArgumentException("outerSize must be >= 0, got " + outerSize);
        }
        if (innerSize < 0) {
            throw new IllegalArgumentException("innerSize must be >= 0, got " + innerSize);
        }
        var rows = new ArrayList<ZkArray<T>>(outerSize);
        for (int i = 0; i < outerSize; i++) {
            rows.add(factory.create(builder, baseName + "_" + i, innerSize));
        }
        return new ZkArray<>(rows);
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

    @FunctionalInterface
    private interface MatrixRowFactory<T extends ZkValue> {
        ZkArray<T> create(SignalBuilder builder, String baseName, int size);
    }
}
