package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;

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
        return new Signal(api.var(name), api);
    }

    /** Declare a public input signal. */
    public Signal publicInput(String name) {
        return new Signal(api.var(name), api);
    }

    /** Declare a public output signal (same as publicInput in the constraint system). */
    public Signal publicOutput(String name) {
        return new Signal(api.var(name), api);
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

    /** Access arr[index] via MUX tree. */
    public Signal arrayAccess(Signal[] arr, Signal index) {
        var vars = new Variable[arr.length];
        for (int i = 0; i < arr.length; i++) vars[i] = arr[i].variable();
        return new Signal(api.arrayAccess(vars, index.variable()), api);
    }

    /** Access to the underlying CircuitAPI (for advanced use / stdlib interop). */
    public CircuitAPI api() { return api; }
}
