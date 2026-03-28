package com.bloxbean.cardano.zeroj.circuit.lib;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;

/**
 * Bit manipulation using the Signal API.
 *
 * <pre>{@code
 * Signal[] bits = SignalBinary.num2Bits(c, value, 8);
 * Signal value = SignalBinary.bits2Num(c, bits);
 * }</pre>
 */
public final class SignalBinary {

    private SignalBinary() {}

    /** Decompose a signal to n bits (LSB first). */
    public static Signal[] num2Bits(SignalBuilder c, Signal value, int nBits) {
        return value.toBinary(nBits);
    }

    /** Recompose a signal from bits (LSB first). */
    public static Signal bits2Num(SignalBuilder c, Signal[] bits) {
        return c.fromBinary(bits);
    }

    /** Bitwise AND of two bit arrays. */
    public static Signal[] bitAnd(Signal[] a, Signal[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Arrays must have equal length");
        var result = new Signal[a.length];
        for (int i = 0; i < a.length; i++) result[i] = a[i].and(b[i]);
        return result;
    }

    /** Bitwise OR of two bit arrays. */
    public static Signal[] bitOr(Signal[] a, Signal[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Arrays must have equal length");
        var result = new Signal[a.length];
        for (int i = 0; i < a.length; i++) result[i] = a[i].or(b[i]);
        return result;
    }

    /** Bitwise XOR of two bit arrays. */
    public static Signal[] bitXor(Signal[] a, Signal[] b) {
        if (a.length != b.length) throw new IllegalArgumentException("Arrays must have equal length");
        var result = new Signal[a.length];
        for (int i = 0; i < a.length; i++) result[i] = a[i].xor(b[i]);
        return result;
    }

    /** Circular left rotation (free — just index shift). */
    public static Signal[] rotateLeft(Signal[] bits, int n) {
        int len = bits.length;
        n = n % len;
        var result = new Signal[len];
        for (int i = 0; i < len; i++) result[i] = bits[(i + n) % len];
        return result;
    }
}
