package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class FieldFFTBLS381Test {

    @Test
    void rootOfUnity_isPrimitive() {
        // omega^(2^32) = 1
        var omega = FieldFFTBLS381.rootOfUnity(32);
        assertFalse(omega.isZero());
        assertFalse(omega.isOne());
        // Square 32 times → should be 1
        var val = omega;
        for (int i = 0; i < 32; i++) val = val.square();
        assertTrue(val.isOne(), "omega^(2^32) must be 1");

        // omega^(2^31) != 1 (primitive)
        var half = FieldFFTBLS381.rootOfUnity(32);
        for (int i = 0; i < 31; i++) half = half.square();
        assertFalse(half.isOne(), "omega^(2^31) must NOT be 1 (primitive check)");
    }

    @Test
    void fft_ifft_roundTrip() {
        int n = 8;
        MontFr381[] coeffs = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            coeffs[i] = MontFr381.fromLong(i + 1);
        }

        var evals = FieldFFTBLS381.fft(coeffs);
        var recovered = FieldFFTBLS381.ifft(evals);

        for (int i = 0; i < n; i++) {
            assertEquals(coeffs[i].toBigInteger(), recovered[i].toBigInteger(),
                    "IFFT(FFT(x)) must equal x at index " + i);
        }
    }

    @Test
    void polyMul_matchesManual() {
        // (1 + 2x) * (3 + 4x) = 3 + 10x + 8x^2
        MontFr381[] a = {MontFr381.fromLong(1), MontFr381.fromLong(2)};
        MontFr381[] b = {MontFr381.fromLong(3), MontFr381.fromLong(4)};

        var result = FieldFFTBLS381.polyMul(a, b);

        assertEquals(3, result.length);
        assertEquals(BigInteger.valueOf(3), result[0].toBigInteger());
        assertEquals(BigInteger.valueOf(10), result[1].toBigInteger());
        assertEquals(BigInteger.valueOf(8), result[2].toBigInteger());
    }

    @Test
    void polyEval_matchesHorner() {
        // f(x) = 1 + 2x + 3x^2, evaluate at x=5
        // f(5) = 1 + 10 + 75 = 86
        MontFr381[] coeffs = {MontFr381.fromLong(1), MontFr381.fromLong(2), MontFr381.fromLong(3)};
        var result = FieldFFTBLS381.polyEval(coeffs, MontFr381.fromLong(5));
        assertEquals(BigInteger.valueOf(86), result.toBigInteger());
    }
}
