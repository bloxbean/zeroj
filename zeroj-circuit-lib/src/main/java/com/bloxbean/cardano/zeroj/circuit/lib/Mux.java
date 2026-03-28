package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * Multiplexer circuit components.
 */
public final class Mux {

    private Mux() {}

    /** 1-bit MUX: returns a if sel==1, b if sel==0. */
    public static Variable mux1(CircuitAPI api, Variable sel, Variable a, Variable b) {
        return api.select(sel, a, b);
    }

    /** 2-bit MUX: selects from 4 inputs based on (sel0, sel1). */
    public static Variable mux2(CircuitAPI api, Variable sel0, Variable sel1,
                                 Variable a, Variable b, Variable c, Variable d) {
        // sel0=0,sel1=0 → a; sel0=1,sel1=0 → b; sel0=0,sel1=1 → c; sel0=1,sel1=1 → d
        var ab = api.select(sel0, b, a);
        var cd = api.select(sel0, d, c);
        return api.select(sel1, cd, ab);
    }

    /** Array access: returns arr[index] via MUX tree. */
    public static Variable arrayAccess(CircuitAPI api, Variable[] arr, Variable index) {
        return api.arrayAccess(arr, index);
    }
}
