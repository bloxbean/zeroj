package com.bloxbean.cardano.zeroj.circuit;

import java.math.BigInteger;

/**
 * A fluent wrapper around {@link Variable} that provides object-oriented circuit operations.
 *
 * <p>Instead of {@code api.mul(a, b)}, write {@code a.mul(b)}.
 * Both styles produce the same constraint graph.</p>
 *
 * <pre>{@code
 * Signal a = c.privateInput("a");
 * Signal b = c.privateInput("b");
 * Signal out = c.publicOutput("out");
 * c.assertEqual(a.mul(b), out);
 * }</pre>
 */
public final class Signal {

    private final Variable variable;
    private final CircuitAPI api;

    Signal(Variable variable, CircuitAPI api) {
        this.variable = variable;
        this.api = api;
    }

    /** The underlying wire variable. */
    public Variable variable() { return variable; }

    // --- Arithmetic ---

    /** Field addition: this + other. */
    public Signal add(Signal other) { return wrap(api.add(variable, other.variable)); }

    /** Field subtraction: this - other. */
    public Signal sub(Signal other) { return wrap(api.sub(variable, other.variable)); }

    /** Field multiplication: this × other. Creates one constraint. */
    public Signal mul(Signal other) { return wrap(api.mul(variable, other.variable)); }

    /** Field negation: -this. */
    public Signal neg() { return wrap(api.neg(variable)); }

    /** Multiplicative inverse: this⁻¹ mod p. */
    public Signal inv() { return wrap(api.inv(variable)); }

    /** Field division: this / other. */
    public Signal div(Signal other) { return wrap(api.div(variable, other.variable)); }

    /** Add a constant: this + value. */
    public Signal add(long value) { return wrap(api.add(variable, api.constant(value))); }

    /** Multiply by a constant: this × value. */
    public Signal mul(long value) { return wrap(api.mul(variable, api.constant(value))); }

    // --- Binary ---

    /** Decompose to nBits binary signals (LSB first). */
    public Signal[] toBinary(int nBits) {
        var bits = api.toBinary(variable, nBits);
        var result = new Signal[bits.length];
        for (int i = 0; i < bits.length; i++) result[i] = wrap(bits[i]);
        return result;
    }

    /** Bitwise XOR: this ⊕ other. Both must be boolean. */
    public Signal xor(Signal other) { return wrap(api.xor(variable, other.variable)); }

    /** Bitwise AND: this ∧ other. Both must be boolean. */
    public Signal and(Signal other) { return wrap(api.and(variable, other.variable)); }

    /** Bitwise OR: this ∨ other. Both must be boolean. */
    public Signal or(Signal other) { return wrap(api.or(variable, other.variable)); }

    /** Bitwise NOT: ¬this. Must be boolean. */
    public Signal not() { return wrap(api.not(variable)); }

    // --- Comparison ---

    /** Returns 1 if this == 0, else 0. */
    public Signal isZero() { return wrap(api.isZero(variable)); }

    /** Returns 1 if this == other, else 0. */
    public Signal isEqual(Signal other) { return wrap(api.isEqual(variable, other.variable)); }

    /** Returns 1 if this < other (unsigned, nBits), else 0. */
    public Signal lessThan(Signal other, int nBits) {
        return wrap(api.lessThan(variable, other.variable, nBits));
    }

    /** Conditional: if this==1 return ifTrue, else ifFalse. this must be boolean. */
    public Signal select(Signal ifTrue, Signal ifFalse) {
        return wrap(api.select(variable, ifTrue.variable, ifFalse.variable));
    }

    // --- Assertions (called on the signal directly) ---

    /** Assert this signal is boolean (0 or 1). */
    public void assertBoolean() { api.assertBoolean(variable); }

    /** Assert this signal fits in nBits: 0 ≤ this < 2^nBits. */
    public void assertInRange(int nBits) { api.assertInRange(variable, nBits); }

    private Signal wrap(Variable v) { return new Signal(v, api); }

    @Override
    public String toString() { return "Signal(" + variable + ")"; }
}
