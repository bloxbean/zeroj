package org.zeroj.circuit.annotation;

import org.zeroj.api.CurveId;
import org.zeroj.api.PublicInputs;
import org.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Ordered witness input accumulator used by generated input builders.
 */
public final class ZkInputMap {
    private static final BigInteger MAX_BYTE = BigInteger.valueOf(255);

    private final Map<String, List<BigInteger>> values = new LinkedHashMap<>();

    public ZkInputMap put(String name, BigInteger value) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
        if (value.signum() < 0) {
            throw new IllegalArgumentException("Input " + name + " must be non-negative, got " + value);
        }
        values.put(name, List.of(value));
        return this;
    }

    public ZkInputMap put(String name, long value) {
        return put(name, BigInteger.valueOf(value));
    }

    /**
     * Validate {@code value} against {@code schemaInput}'s declared type/bit-width bounds and
     * record it under {@code signalName}.
     */
    public ZkInputMap putChecked(ZkCircuitSchema.Input schemaInput, String signalName, BigInteger value) {
        Objects.requireNonNull(schemaInput, "schemaInput");
        Objects.requireNonNull(signalName, "signalName");
        requireInSchemaRange(schemaInput, signalName, value);
        return put(signalName, value);
    }

    public ZkInputMap putArray(String baseName, List<BigInteger> inputValues) {
        Objects.requireNonNull(baseName, "baseName");
        Objects.requireNonNull(inputValues, "inputValues");
        for (int i = 0; i < inputValues.size(); i++) {
            put(baseName + "_" + i, inputValues.get(i));
        }
        return this;
    }

    /**
     * Validate every element against {@code schemaInput}'s declared type/bit-width bounds before
     * storing any entry.
     */
    public ZkInputMap putArrayChecked(ZkCircuitSchema.Input schemaInput, List<BigInteger> inputValues) {
        Objects.requireNonNull(schemaInput, "schemaInput");
        Objects.requireNonNull(inputValues, "inputValues");
        for (int i = 0; i < inputValues.size(); i++) {
            requireInSchemaRange(schemaInput, schemaInput.name() + "_" + i, inputValues.get(i));
        }
        return putArray(schemaInput.name(), inputValues);
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

    /**
     * Validate every nested element against {@code schemaInput}'s declared type/bit-width bounds
     * before storing any entry.
     */
    public ZkInputMap putNestedArrayChecked(
            ZkCircuitSchema.Input schemaInput,
            List<? extends List<BigInteger>> inputValues) {
        Objects.requireNonNull(schemaInput, "schemaInput");
        Objects.requireNonNull(inputValues, "inputValues");
        for (int row = 0; row < inputValues.size(); row++) {
            List<BigInteger> rowValues = Objects.requireNonNull(inputValues.get(row),
                    "inputValues[" + row + "]");
            for (int col = 0; col < rowValues.size(); col++) {
                requireInSchemaRange(schemaInput,
                        schemaInput.name() + "_" + row + "_" + col,
                        rowValues.get(col));
            }
        }
        return putNestedArray(schemaInput.name(), inputValues);
    }

    /**
     * Validate that every input declared by {@code schema} is present, no unknown keys exist,
     * every value satisfies its declared type/bit-width bounds, and every value is canonical in
     * {@code [0, p)} for {@code curve}.
     */
    public void validate(ZkCircuitSchema schema, CurveId curve) {
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(curve, "curve");
        validate(schema, FieldConfig.forCurve(curve));
    }

    /**
     * Validate all inputs against {@code schema} and {@code field}'s canonical range {@code [0, p)}.
     */
    public void validate(ZkCircuitSchema schema, FieldConfig field) {
        Objects.requireNonNull(schema, "schema");
        Objects.requireNonNull(field, "field");
        BigInteger prime = field.prime();
        Set<String> expectedSignals = new HashSet<>();
        for (ZkCircuitSchema.Input input : schema.inputs()) {
            for (String signalName : input.signalNames()) {
                expectedSignals.add(signalName);
                List<BigInteger> vals = values.get(signalName);
                if (vals == null || vals.isEmpty()) {
                    throw new IllegalStateException("Missing input: " + signalName);
                }
                if (vals.size() != 1) {
                    throw new IllegalArgumentException(
                            "Input " + signalName + " must have exactly 1 value, got " + vals.size());
                }
                BigInteger value = vals.getFirst();
                requireInSchemaRange(input, signalName, value);
                if (value.compareTo(prime) >= 0) {
                    throw new IllegalArgumentException(
                            "Input " + signalName + " is not canonical for " + field.name()
                                    + " (expected < p): " + value);
                }
            }
        }
        for (String key : values.keySet()) {
            if (!expectedSignals.contains(key)) {
                throw new IllegalArgumentException("Unknown input not declared in schema: " + key);
            }
        }
    }

    public static void requireInSchemaRange(
            ZkCircuitSchema.Input schemaInput,
            String signalName,
            BigInteger value) {
        Objects.requireNonNull(schemaInput, "schemaInput");
        Objects.requireNonNull(signalName, "signalName");
        Objects.requireNonNull(value, signalName);
        if (value.signum() < 0) {
            throw new IllegalArgumentException(
                    "Input " + signalName + " must be non-negative, got " + value);
        }
        switch (schemaInput.kind()) {
            case BOOL, BITS -> {
                if (value.compareTo(BigInteger.ONE) > 0) {
                    throw new IllegalArgumentException(
                            "Input " + signalName + " must be 0 or 1, got " + value);
                }
            }
            case BYTES -> {
                if (value.compareTo(MAX_BYTE) > 0) {
                    throw new IllegalArgumentException(
                            "Input " + signalName + " must be in [0, 255], got " + value);
                }
            }
            case UINT -> {
                if (value.bitLength() > schemaInput.bits()) {
                    throw new IllegalArgumentException(
                            "Input " + signalName + " exceeds " + schemaInput.bits()
                                    + "-bit unsigned range: " + value);
                }
            }
            case FIELD -> {
                // Non-negative already enforced; curve-specific < p checked in validate()/WitnessCalculator.
            }
        }
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
