package org.zeroj.circuit.lib;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.Variable;

import java.util.Objects;

/**
 * Unsigned bit-width range check — constrains {@code 0 <= value < 2^nBits}.
 *
 * <p>Decomposes {@code value} into {@code nBits} boolean wires via
 * {@link CircuitAPI#toBinary(Variable, int)} (enforcing {@code 1 <= nBits <= 253}).</p>
 *
 * <p><b>Scope note:</b> This checks {@code value < 2^nBits}; it does <em>not</em> perform a
 * strict {@code < p} prime-modulus alias check on an arbitrary 254/255-bit bit vector. For
 * 256-bit big-endian BLS12-381 canonical-key checks, compare explicitly against the BLS12-381
 * scalar modulus (as in {@code ZkJmtCanonicalKey} / {@code ZkMpf}).</p>
 */
public final class RangeCheck {

    private RangeCheck() {}

    /**
     * Assert that {@code value} fits in {@code nBits} unsigned bits ({@code 0 <= value < 2^nBits}).
     *
     * @param api   circuit API
     * @param value field element to range-constrain
     * @param nBits unsigned bit width in {@code [1, 253]}
     */
    public static void check(CircuitAPI api, Variable value, int nBits) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(value, "value");
        api.toBinary(value, nBits);
    }

    /** Signal API wrapper for {@link #check(CircuitAPI, Variable, int)}. */
    public static void check(SignalBuilder c, Signal value, int nBits) {
        Objects.requireNonNull(c, "c");
        Objects.requireNonNull(value, "value");
        if (!value.isFrom(c)) {
            throw new IllegalArgumentException("Signal does not belong to the given SignalBuilder");
        }
        check(c.api(), value.variable(), nBits);
    }
}
