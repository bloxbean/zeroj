package com.bloxbean.cardano.zeroj.circuit;

import java.util.*;

/**
 * Proof-system-agnostic representation of an arithmetic circuit.
 *
 * <p>Contains an ordered list of gates and metadata about which variables
 * are public inputs, secret inputs, and intermediates. The gate list is
 * in topological order (each gate's inputs are defined before the gate).</p>
 *
 * <p>Wire numbering follows the iden3/circom convention:
 * <ul>
 *   <li>Wire 0: constant "1"</li>
 *   <li>Wires 1..nPub: public input variables (in declaration order)</li>
 *   <li>Wires nPub+1..nPub+nSec: secret input variables</li>
 *   <li>Remaining wires: intermediate variables</li>
 * </ul>
 *
 * <p>{@code expectedField} (nullable): if set, any attempt to compile or
 * calculate a witness for a curve whose field differs from this value
 * throws. Gadgets that depend on field-specific constants (e.g. Poseidon)
 * use {@link CircuitAPI#requireField} during {@code define()} to record
 * this expectation and catch field-vs-curve mismatches at compile time
 * rather than silently producing non-canonical outputs.
 */
public record ConstraintGraph(
        String name,
        List<Gate> gates,
        Variable oneWire,
        List<Variable> publicInputs,
        List<Variable> secretInputs,
        List<Variable> intermediateVars,
        int numWires,
        FieldConfig expectedField
) {
    public ConstraintGraph {
        gates = List.copyOf(gates);
        publicInputs = List.copyOf(publicInputs);
        secretInputs = List.copyOf(secretInputs);
        intermediateVars = List.copyOf(intermediateVars);
    }

    /** Convenience overload for callers that don't set an expected field. */
    public ConstraintGraph(String name, List<Gate> gates, Variable oneWire,
                           List<Variable> publicInputs, List<Variable> secretInputs,
                           List<Variable> intermediateVars, int numWires) {
        this(name, gates, oneWire, publicInputs, secretInputs, intermediateVars, numWires, null);
    }

    /** Total number of input signals (public + secret). */
    public int numInputs() { return publicInputs.size() + secretInputs.size(); }

    /**
     * Enforces the field dependency recorded by {@link CircuitAPI#requireField(FieldConfig)}.
     *
     * <p>This check belongs on the graph, not only on {@link CircuitBuilder}: the graph and
     * each compiler/witness calculator are public APIs, so callers can legitimately invoke
     * them directly. Silently evaluating BLS12-381 Poseidon/Jubjub constants in BN254 changes
     * the intended relation.
     *
     * @throws IllegalStateException if this graph declared a different field
     */
    public void requireCompatibleField(FieldConfig actual) {
        Objects.requireNonNull(actual, "actual");
        if (expectedField != null && !expectedField.equals(actual)) {
            throw new IllegalStateException(
                    "Field mismatch: circuit declared expected field " + expectedField.name()
                            + " (via requireField) but compilation / witness calculation "
                            + "was requested for " + actual.name() + ". Typical cause: a "
                            + "gadget was given Poseidon/Jubjub parameters for a field that "
                            + "does not match the target. Use matching parameters and field.");
        }
    }

    /** Get all named variables (public + secret). */
    public Map<String, Variable> namedVariables() {
        var map = new LinkedHashMap<String, Variable>();
        for (var v : publicInputs) if (v.name() != null) map.put(v.name(), v);
        for (var v : secretInputs) if (v.name() != null) map.put(v.name(), v);
        return Collections.unmodifiableMap(map);
    }
}
