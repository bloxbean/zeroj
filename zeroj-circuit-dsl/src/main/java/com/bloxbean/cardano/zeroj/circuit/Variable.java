package com.bloxbean.cardano.zeroj.circuit;

/**
 * An opaque reference to a wire in the arithmetic circuit.
 *
 * <p>Variables represent signals (field elements) that flow through the circuit.
 * They do not carry runtime values during circuit definition — they are symbolic
 * references that the constraint compiler resolves into wire indices.</p>
 *
 * @param id    internal wire index
 * @param name  human-readable name (for debugging), null for intermediate wires
 */
public record Variable(int id, String name) {

    /** Create an unnamed intermediate variable. */
    public static Variable intermediate(int id) {
        return new Variable(id, null);
    }

    @Override
    public String toString() {
        return name != null ? name + "(w" + id + ")" : "w" + id;
    }
}
