package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

/**
 * Comparison operations using the Signal API.
 *
 * <pre>{@code
 * Signal older = SignalComparators.lessThan(c, age, threshold, 8);
 * Signal inBounds = SignalComparators.inRange(c, value, min, max, 16);
 * }</pre>
 */
public final class SignalComparators {

    private SignalComparators() {}

    /** Returns 1 if a < b (n-bit unsigned), else 0. */
    public static Signal lessThan(SignalBuilder c, Signal a, Signal b, int nBits) {
        return c.wrap(c.api().lessThan(a.variable(), b.variable(), nBits));
    }

    /** Returns 1 if a > b, else 0. */
    public static Signal greaterThan(SignalBuilder c, Signal a, Signal b, int nBits) {
        return lessThan(c, b, a, nBits);
    }

    /** Returns 1 if a <= b, else 0. */
    public static Signal lessOrEqual(SignalBuilder c, Signal a, Signal b, int nBits) {
        return greaterThan(c, a, b, nBits).not();
    }

    /** Returns 1 if a >= b, else 0. */
    public static Signal greaterOrEqual(SignalBuilder c, Signal a, Signal b, int nBits) {
        return lessThan(c, a, b, nBits).not();
    }

    /** Returns 1 if min <= value <= max, else 0. */
    public static Signal inRange(SignalBuilder c, Signal value, Signal min, Signal max, int nBits) {
        return greaterOrEqual(c, value, min, nBits).and(lessOrEqual(c, value, max, nBits));
    }

    /** Returns the minimum of a and b. */
    public static Signal min(SignalBuilder c, Signal a, Signal b, int nBits) {
        return lessThan(c, a, b, nBits).select(a, b);
    }

    /** Returns the maximum of a and b. */
    public static Signal max(SignalBuilder c, Signal a, Signal b, int nBits) {
        return lessThan(c, a, b, nBits).select(b, a);
    }
}
