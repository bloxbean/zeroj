package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * Comparison circuit components.
 */
public final class Comparators {

    private Comparators() {}

    /** Returns 1 if a < b (unsigned, nBits-bit comparison), else 0. */
    public static Variable lessThan(CircuitAPI api, Variable a, Variable b, int nBits) {
        return api.lessThan(a, b, nBits);
    }

    /** Returns 1 if a > b, else 0. */
    public static Variable greaterThan(CircuitAPI api, Variable a, Variable b, int nBits) {
        return lessThan(api, b, a, nBits);
    }

    /** Returns 1 if a <= b, else 0. */
    public static Variable lessOrEqual(CircuitAPI api, Variable a, Variable b, int nBits) {
        return api.not(greaterThan(api, a, b, nBits));
    }

    /** Returns 1 if a >= b, else 0. */
    public static Variable greaterOrEqual(CircuitAPI api, Variable a, Variable b, int nBits) {
        return api.not(lessThan(api, a, b, nBits));
    }

    /** Returns 1 if min <= value <= max, else 0. */
    public static Variable inRange(CircuitAPI api, Variable value, Variable min, Variable max, int nBits) {
        var geMin = greaterOrEqual(api, value, min, nBits);
        var leMax = lessOrEqual(api, value, max, nBits);
        return api.and(geMin, leMax);
    }

    /** Returns the minimum of a and b. */
    public static Variable min(CircuitAPI api, Variable a, Variable b, int nBits) {
        var aLtB = lessThan(api, a, b, nBits);
        return api.select(aLtB, a, b);
    }

    /** Returns the maximum of a and b. */
    public static Variable max(CircuitAPI api, Variable a, Variable b, int nBits) {
        var aLtB = lessThan(api, a, b, nBits);
        return api.select(aLtB, b, a);
    }
}
