package org.zeroj.circuit;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Builder for the {@link Signal}-based circuit API.
 *
 * <p>Provides methods to declare inputs/outputs and assert constraints
 * using the fluent {@link Signal} type.</p>
 *
 * <pre>{@code
 * public void define(SignalBuilder c) {
 *     Signal a = c.privateInput("a");
 *     Signal b = c.privateInput("b");
 *     Signal out = c.publicOutput("out");
 *     c.assertEqual(a.mul(b), out);
 * }
 * }</pre>
 */
public final class SignalBuilder {

    private final CircuitAPI api;

    SignalBuilder(CircuitAPI api) {
        this.api = api;
    }

    // --- Input/Output declaration ---

    /** Declare a private (secret) input signal. */
    public Signal privateInput(String name) {
        return new Signal(api.secretInputVar(name), api);
    }

    /** Declare a public input signal. */
    public Signal publicInput(String name) {
        return new Signal(api.publicInputVar(name), api);
    }

    /** Declare a public output signal (same as publicInput in the constraint system). */
    public Signal publicOutput(String name) {
        return new Signal(api.publicInputVar(name), api);
    }

    /** Look up a previously declared signal by name. */
    public Signal signal(String name) {
        return new Signal(api.var(name), api);
    }

    // --- Constants ---

    /** Create a constant signal. */
    public Signal constant(long value) {
        return new Signal(api.constant(value), api);
    }

    /** Create a constant signal. */
    public Signal constant(BigInteger value) {
        return new Signal(api.constant(value), api);
    }

    // --- Constraints ---

    /** Assert two signals are equal. */
    public void assertEqual(Signal a, Signal b) {
        api.assertEqual(a.variable(), b.variable());
    }

    /** Assert a signal is not equal to another. */
    public void assertNotEqual(Signal a, Signal b) {
        api.assertNotEqual(a.variable(), b.variable());
    }

    // --- Binary recomposition ---

    /** Recompose a field element from binary signals (LSB first). */
    public Signal fromBinary(Signal[] bits) {
        var vars = new Variable[bits.length];
        for (int i = 0; i < bits.length; i++) vars[i] = bits[i].variable();
        return new Signal(api.fromBinary(vars), api);
    }

    // --- Array access ---

    /**
     * Access {@code arr[index]} via MUX scan, constraining {@code 0 <= index < arr.length}
     * (ADR-0065).
     *
     * @throws IllegalArgumentException if {@code arr} is empty
     */
    public Signal arrayAccess(Signal[] arr, Signal index) {
        Objects.requireNonNull(arr, "arr");
        Objects.requireNonNull(index, "index");
        var vars = new Variable[arr.length];
        for (int i = 0; i < arr.length; i++) {
            vars[i] = Objects.requireNonNull(arr[i], "arr[" + i + "]").variable();
        }
        return new Signal(api.arrayAccess(vars, index.variable()), api);
    }

    /**
     * Total-function lookup returning {@code arr[index]} when {@code 0 <= index < arr.length} and
     * {@code 0} otherwise, without emitting an index bounds constraint (ADR-0065).
     *
     * <p>Only use this when the caller independently constrains {@code index} on active rows and
     * masks inactive padding rows; otherwise use {@link #arrayAccess(Signal[], Signal)}.</p>
     */
    public Signal arrayAccessOrZero(Signal[] arr, Signal index) {
        Objects.requireNonNull(arr, "arr");
        Objects.requireNonNull(index, "index");
        var vars = new Variable[arr.length];
        for (int i = 0; i < arr.length; i++) {
            vars[i] = Objects.requireNonNull(arr[i], "arr[" + i + "]").variable();
        }
        return new Signal(api.arrayAccessOrZero(vars, index.variable()), api);
    }

    /** Wrap a Variable as a Signal (for stdlib interop). */
    public Signal wrap(Variable variable) {
        return new Signal(variable, api);
    }

    /** Access to the underlying CircuitAPI (for advanced use / stdlib interop). */
    public CircuitAPI api() { return api; }
}
