package org.zeroj.circuit.lib;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Variable;

import java.util.Objects;

/**
 * Bit manipulation circuit utilities.
 */
public final class Binary {

    private Binary() {}

    /** Decompose a field element to n bits (LSB first). */
    public static Variable[] num2Bits(CircuitAPI api, Variable value, int nBits) {
        return api.toBinary(value, nBits);
    }

    /** Recompose a field element from bits (LSB first). */
    public static Variable bits2Num(CircuitAPI api, Variable[] bits) {
        return api.fromBinary(bits);
    }

    /** Bitwise AND of two bit arrays (same length). */
    public static Variable[] bitAnd(CircuitAPI api, Variable[] a, Variable[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Bit arrays must have equal length");
        var result = new Variable[a.length];
        for (int i = 0; i < a.length; i++) result[i] = api.and(a[i], b[i]);
        return result;
    }

    /** Bitwise OR of two bit arrays. */
    public static Variable[] bitOr(CircuitAPI api, Variable[] a, Variable[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Bit arrays must have equal length");
        var result = new Variable[a.length];
        for (int i = 0; i < a.length; i++) result[i] = api.or(a[i], b[i]);
        return result;
    }

    /** Bitwise XOR of two bit arrays. */
    public static Variable[] bitXor(CircuitAPI api, Variable[] a, Variable[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Bit arrays must have equal length");
        var result = new Variable[a.length];
        for (int i = 0; i < a.length; i++) result[i] = api.xor(a[i], b[i]);
        return result;
    }

    /**
     * Circular left rotation of an LSB-first bit array (free — index remapping only).
     *
     * <p>Moves bit {@code j} to bit position {@code (j + n) mod len}, so {@code rotateLeft(0x01, 1)}
     * produces {@code 0x02}. Negative {@code n} rotates right by {@code -n}.</p>
     */
    public static Variable[] rotateLeft(Variable[] bits, int n) {
        Objects.requireNonNull(bits, "bits");
        int len = bits.length;
        if (len == 0) {
            throw new IllegalArgumentException("bits must not be empty");
        }
        int shift = Math.floorMod(n, len);
        var result = new Variable[len];
        for (int i = 0; i < len; i++) {
            result[i] = bits[(i - shift + len) % len];
        }
        return result;
    }

    /**
     * Logical right shift of an LSB-first bit array with zero fill (free — index remapping only).
     *
     * @throws IllegalArgumentException if {@code n < 0}
     */
    public static Variable[] shiftRight(CircuitAPI api, Variable[] bits, int n) {
        Objects.requireNonNull(api, "api");
        Objects.requireNonNull(bits, "bits");
        if (n < 0) {
            throw new IllegalArgumentException("Shift amount must be non-negative: " + n);
        }
        var result = new Variable[bits.length];
        var zero = api.constant(0);
        for (int i = 0; i < bits.length; i++) {
            result[i] = (n < bits.length - i) ? bits[i + n] : zero;
        }
        return result;
    }
}
