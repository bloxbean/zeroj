package org.zeroj.circuit.lib;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Signal;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.Variable;

/**
 * Deprecated misnamed wrapper around {@link RangeCheck}.
 *
 * <p><b>Important:</b> Despite its historical name, this gadget does <em>not</em> implement
 * circomlib's {@code AliasCheck()} ({@code bits < p}). It delegates to
 * {@link CircuitAPI#toBinary(Variable, int)}, which enforces {@code 0 <= value < 2^nBits} for
 * {@code 1 <= nBits <= 253} — throwing at 254/255 bits and rejecting ~72.4% of valid BLS12-381
 * scalar field elements at {@code nBits = 253}.</p>
 *
 * @deprecated Misnamed: enforces {@code 0 <= value < 2^nBits}, not {@code < p}. Use
 *             {@link RangeCheck} for unsigned bit-width range checks.
 */
@Deprecated(forRemoval = true)
public final class AliasCheck {

    private AliasCheck() {}

    /**
     * Assert that {@code value} fits in {@code nBits} unsigned bits ({@code 0 <= value < 2^nBits}).
     *
     * @deprecated Use {@link RangeCheck#check(CircuitAPI, Variable, int)}.
     */
    @Deprecated(forRemoval = true)
    public static void check(CircuitAPI api, Variable value, int nBits) {
        RangeCheck.check(api, value, nBits);
    }

    /**
     * Signal API wrapper.
     *
     * @deprecated Use {@link RangeCheck#check(SignalBuilder, Signal, int)}.
     */
    @Deprecated(forRemoval = true)
    public static void check(SignalBuilder c, Signal value, int nBits) {
        RangeCheck.check(c, value, nBits);
    }
}
