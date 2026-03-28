package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

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

    /** Circular left rotation of a bit array (free — just index shifting). */
    public static Variable[] rotateLeft(Variable[] bits, int n) {
        int len = bits.length;
        n = n % len;
        var result = new Variable[len];
        for (int i = 0; i < len; i++) result[i] = bits[(i + n) % len];
        return result;
    }

    /** Logical right shift of a bit array with zero fill (free — index shifting). */
    public static Variable[] shiftRight(CircuitAPI api, Variable[] bits, int n) {
        var result = new Variable[bits.length];
        var zero = api.constant(0);
        for (int i = 0; i < bits.length; i++) {
            result[i] = (i + n < bits.length) ? bits[i + n] : zero;
        }
        return result;
    }
}
