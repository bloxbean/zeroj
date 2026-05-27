package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.api.PublicInputs;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Ordered witness input accumulator used by generated input builders.
 */
public final class ZkInputMap {
    private final Map<String, List<BigInteger>> values = new LinkedHashMap<>();

    public ZkInputMap put(String name, BigInteger value) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
        values.put(name, List.of(value));
        return this;
    }

    public ZkInputMap put(String name, long value) {
        return put(name, BigInteger.valueOf(value));
    }

    public ZkInputMap putArray(String baseName, List<BigInteger> inputValues) {
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(inputValues, "inputValues");
        for (int i = 0; i < inputValues.size(); i++) {
            put(baseName + "_" + i, inputValues.get(i));
        }
        return this;
    }

    public ZkInputMap putNestedArray(String baseName, List<? extends List<BigInteger>> inputValues) {
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(inputValues, "inputValues");
        for (int row = 0; row < inputValues.size(); row++) {
            List<BigInteger> rowValues = Objects.requireNonNull(inputValues.get(row),
                    "inputValues[" + row + "]");
            for (int col = 0; col < rowValues.size(); col++) {
                put(baseName + "_" + row + "_" + col, rowValues.get(col));
            }
        }
        return this;
    }

    public Map<String, List<BigInteger>> toWitnessMap() {
        var copy = new LinkedHashMap<String, List<BigInteger>>();
        values.forEach((name, value) -> copy.put(name, List.copyOf(value)));
        return Collections.unmodifiableMap(copy);
    }

    public List<BigInteger> publicValues(ZkCircuitSchema schema) {
        Objects.requireNonNull(schema, "schema");
        var out = new ArrayList<BigInteger>();
        for (String name : schema.publicInputs().names()) {
            var value = values.get(name);
            if (value == null || value.isEmpty()) {
                throw new IllegalStateException("Missing public input: " + name);
            }
            out.add(value.getFirst());
        }
        return List.copyOf(out);
    }

    public PublicInputs publicInputs(ZkCircuitSchema schema) {
        return new PublicInputs(publicValues(schema));
    }
}
