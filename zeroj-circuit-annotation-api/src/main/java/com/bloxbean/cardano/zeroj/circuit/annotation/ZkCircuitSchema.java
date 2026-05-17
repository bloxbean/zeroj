package com.bloxbean.cardano.zeroj.circuit.annotation;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Runtime metadata for a generated annotated circuit shape.
 */
public record ZkCircuitSchema(
        String name,
        List<Parameter> parameters,
        InputGroup publicInputs,
        InputGroup secretInputs) {

    public ZkCircuitSchema {
        Objects.requireNonNull(name, "name");
        parameters = List.copyOf(Objects.requireNonNull(parameters, "parameters"));
        Objects.requireNonNull(publicInputs, "publicInputs");
        Objects.requireNonNull(secretInputs, "secretInputs");
    }

    public static ZkCircuitSchema of(
            String name,
            List<Parameter> parameters,
            List<Input> publicInputs,
            List<Input> secretInputs) {
        return new ZkCircuitSchema(
                name,
                parameters,
                new InputGroup(publicInputs),
                new InputGroup(secretInputs));
    }

    public List<Input> inputs() {
        var inputs = new ArrayList<Input>(publicInputs.inputs().size() + secretInputs.inputs().size());
        inputs.addAll(publicInputs.inputs());
        inputs.addAll(secretInputs.inputs());
        return List.copyOf(inputs);
    }

    public Optional<Input> findInput(String name) {
        Objects.requireNonNull(name, "name");
        var exact = inputs().stream()
                .filter(input -> input.name().equals(name))
                .findFirst();
        if (exact.isPresent()) {
            return exact;
        }
        return inputs().stream()
                .filter(input -> input.signalNames().contains(name))
                .findFirst();
    }

    public Input input(String name) {
        return findInput(name)
                .orElseThrow(() -> new IllegalArgumentException("Unknown circuit input: " + name));
    }

    public record Parameter(String name, String type, String value) {
        public Parameter {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(type, "type");
            Objects.requireNonNull(value, "value");
        }
    }

    public record InputGroup(List<Input> inputs) {
        public InputGroup {
            inputs = List.copyOf(Objects.requireNonNull(inputs, "inputs"));
        }

        public List<String> names() {
            return inputs.stream()
                    .flatMap(input -> input.signalNames().stream())
                    .toList();
        }
    }

    public record Input(
            String name,
            Visibility visibility,
            Kind kind,
            int bits,
            int size,
            boolean array,
            List<String> signalNames) {

        public Input {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(visibility, "visibility");
            Objects.requireNonNull(kind, "kind");
            if (bits < -1 || bits == 0) {
                throw new IllegalArgumentException("bits must be -1 or positive");
            }
            if (size <= 0) {
                throw new IllegalArgumentException("size must be positive");
            }
            validateKind(kind, bits, array);
            signalNames = List.copyOf(Objects.requireNonNull(signalNames, "signalNames"));
            if (signalNames.size() != size) {
                throw new IllegalArgumentException("signalNames size must match input size");
            }
        }

        public static Input scalar(String name, Visibility visibility, Kind kind, int bits) {
            return new Input(name, visibility, kind, bits, 1, false, List.of(name));
        }

        public static Input array(String name, Visibility visibility, Kind kind, int bits, int size) {
            var names = new ArrayList<String>(size);
            for (int i = 0; i < size; i++) {
                names.add(name + "_" + i);
            }
            return new Input(name, visibility, kind, bits, size, true, names);
        }

        private static void validateKind(Kind kind, int bits, boolean array) {
            switch (kind) {
                case FIELD -> {
                    if (bits != -1) {
                        throw new IllegalArgumentException("FIELD inputs must use bits = -1");
                    }
                }
                case BOOL -> {
                    if (bits != 1) {
                        throw new IllegalArgumentException("BOOL inputs must use bits = 1");
                    }
                }
                case UINT -> {
                    if (bits <= 0) {
                        throw new IllegalArgumentException("UINT inputs must use a positive bit width");
                    }
                }
                case BITS -> {
                    if (!array || bits != 1) {
                        throw new IllegalArgumentException("BITS inputs must be arrays with bits = 1");
                    }
                }
                case BYTES -> {
                    if (!array || bits != 8) {
                        throw new IllegalArgumentException("BYTES inputs must be arrays with bits = 8");
                    }
                }
            }
        }
    }

    public enum Visibility {
        PUBLIC,
        SECRET
    }

    public enum Kind {
        FIELD,
        BOOL,
        UINT,
        BITS,
        BYTES
    }
}
