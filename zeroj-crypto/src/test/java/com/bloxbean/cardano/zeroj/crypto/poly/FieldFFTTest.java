package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for NTT/FFT over BN254 scalar field.
 *
 * <p>Tests validate:
 * <ul>
 *   <li>Root of unity properties (primitive, correct order)</li>
 *   <li>FFT/IFFT round-trip identity</li>
 *   <li>Polynomial evaluation consistency (FFT vs Horner)</li>
 *   <li>Polynomial multiplication (FFT-based vs naive)</li>
 *   <li>Various domain sizes (2, 4, 8, 16, 256, 1024)</li>
 * </ul></p>
 */
class FieldFFTTest {

    static final BigInteger R = MontFr254.modulus();
    static final Random RNG = new Random(42);

    // --- Root of unity tests ---

    @Test
    void rootOfUnity_order2() {
        var omega = FieldFFT.rootOfUnity(1);
        // omega^2 = 1
        assertTrue(omega.square().isOne(), "omega_1^2 should be 1");
        // omega != 1
        assertFalse(omega.isOne(), "omega_1 should not be 1");
        // omega should be -1 (p-1)
        assertEquals(R.subtract(BigInteger.ONE), omega.toBigInteger(), "omega_1 should be -1 mod r");
    }

    @Test
    void rootOfUnity_order4() {
        var omega = FieldFFT.rootOfUnity(2);
        // omega^4 = 1
        assertTrue(omega.square().square().isOne(), "omega_2^4 should be 1");
        // omega^2 = -1
        assertEquals(R.subtract(BigInteger.ONE), omega.square().toBigInteger(), "omega_2^2 should be -1");
    }

    @Test
    void rootOfUnity_order8() {
        var omega = FieldFFT.rootOfUnity(3);
        // omega^i for i in 1..7 should NOT be 1; omega^8 should be 1
        var w = omega;
        for (int i = 1; i <= 7; i++) {
            assertFalse(w.isOne(), "omega_3^" + i + " should not be 1");
            w = w.mul(omega);
        }
        assertTrue(w.isOne(), "omega_3^8 should be 1");
    }

    @Test
    void rootOfUnity_order1024() {
        var omega = FieldFFT.rootOfUnity(10);
        // omega^1024 = 1
        var w = omega;
        for (int i = 1; i < 1024; i++) {
            w = w.mul(omega);
        }
        assertTrue(w.isOne(), "omega_10^1024 should be 1");
        // omega^512 = -1
        w = MontFr254.ONE;
        for (int i = 0; i < 512; i++) w = w.mul(omega);
        assertEquals(R.subtract(BigInteger.ONE), w.toBigInteger(), "omega_10^512 should be -1");
    }

    @Test
    void rootOfUnity_invalidLogN_throws() {
        assertThrows(IllegalArgumentException.class, () -> FieldFFT.rootOfUnity(0));
        assertThrows(IllegalArgumentException.class, () -> FieldFFT.rootOfUnity(29));
    }

    // --- FFT/IFFT round-trip ---

    @Test
    void fftIfft_roundTrip_size2() {
        var coeffs = new MontFr254[]{MontFr254.fromLong(3), MontFr254.fromLong(7)};
        var evals = FieldFFT.fft(coeffs);
        var recovered = FieldFFT.ifft(evals);
        assertArrayEqualsFr(coeffs, recovered);
    }

    @Test
    void fftIfft_roundTrip_size4() {
        var coeffs = new MontFr254[]{
                MontFr254.fromLong(1), MontFr254.fromLong(2),
                MontFr254.fromLong(3), MontFr254.fromLong(4)};
        assertArrayEqualsFr(coeffs, FieldFFT.ifft(FieldFFT.fft(coeffs)));
    }

    @Test
    void fftIfft_roundTrip_size8() {
        var coeffs = randomPoly(8);
        assertArrayEqualsFr(coeffs, FieldFFT.ifft(FieldFFT.fft(coeffs)));
    }

    @Test
    void fftIfft_roundTrip_size256() {
        var coeffs = randomPoly(256);
        assertArrayEqualsFr(coeffs, FieldFFT.ifft(FieldFFT.fft(coeffs)));
    }

    @Test
    void fftIfft_roundTrip_size1024() {
        var coeffs = randomPoly(1024);
        assertArrayEqualsFr(coeffs, FieldFFT.ifft(FieldFFT.fft(coeffs)));
    }

    @Test
    void fftIfft_roundTrip_allZeros() {
        var coeffs = new MontFr254[]{MontFr254.ZERO, MontFr254.ZERO, MontFr254.ZERO, MontFr254.ZERO};
        var recovered = FieldFFT.ifft(FieldFFT.fft(coeffs));
        for (var c : recovered) assertTrue(c.isZero());
    }

    @Test
    void fftIfft_roundTrip_constant() {
        var coeffs = new MontFr254[]{MontFr254.fromLong(42), MontFr254.ZERO, MontFr254.ZERO, MontFr254.ZERO};
        var recovered = FieldFFT.ifft(FieldFFT.fft(coeffs));
        assertEquals(BigInteger.valueOf(42), recovered[0].toBigInteger());
        for (int i = 1; i < 4; i++) assertTrue(recovered[i].isZero());
    }

    // --- FFT evaluation consistency ---

    @Test
    void fft_matchesHornerEvaluation_size4() {
        var coeffs = new MontFr254[]{
                MontFr254.fromLong(5), MontFr254.fromLong(3),
                MontFr254.fromLong(7), MontFr254.fromLong(11)};
        // p(x) = 5 + 3x + 7x^2 + 11x^3
        var evals = FieldFFT.fft(coeffs);
        var omega = FieldFFT.rootOfUnity(2); // 4th root of unity

        // evals[i] should equal p(omega^i)
        var w = MontFr254.ONE;
        for (int i = 0; i < 4; i++) {
            var expected = FieldFFT.polyEval(coeffs, w);
            assertEquals(expected.toBigInteger(), evals[i].toBigInteger(),
                    "FFT eval at omega^" + i + " should match Horner");
            w = w.mul(omega);
        }
    }

    @Test
    void fft_matchesHornerEvaluation_size8() {
        var coeffs = randomPoly(8);
        var evals = FieldFFT.fft(coeffs);
        var omega = FieldFFT.rootOfUnity(3);

        var w = MontFr254.ONE;
        for (int i = 0; i < 8; i++) {
            var expected = FieldFFT.polyEval(coeffs, w);
            assertEquals(expected.toBigInteger(), evals[i].toBigInteger(),
                    "FFT eval at omega^" + i + " should match Horner");
            w = w.mul(omega);
        }
    }

    // --- Polynomial multiplication ---

    @Test
    void polyMul_linear() {
        // (1 + 2x) * (3 + 4x) = 3 + 10x + 8x^2
        var a = new MontFr254[]{MontFr254.fromLong(1), MontFr254.fromLong(2)};
        var b = new MontFr254[]{MontFr254.fromLong(3), MontFr254.fromLong(4)};
        var c = FieldFFT.polyMul(a, b);

        assertEquals(3, c.length);
        assertEquals(BigInteger.valueOf(3), c[0].toBigInteger());
        assertEquals(BigInteger.valueOf(10), c[1].toBigInteger());
        assertEquals(BigInteger.valueOf(8), c[2].toBigInteger());
    }

    @Test
    void polyMul_quadratic() {
        // (1 + x + x^2) * (2 + 3x) = 2 + 5x + 5x^2 + 3x^3
        var a = new MontFr254[]{MontFr254.fromLong(1), MontFr254.fromLong(1), MontFr254.fromLong(1)};
        var b = new MontFr254[]{MontFr254.fromLong(2), MontFr254.fromLong(3)};
        var c = FieldFFT.polyMul(a, b);

        assertEquals(4, c.length);
        assertEquals(BigInteger.valueOf(2), c[0].toBigInteger());
        assertEquals(BigInteger.valueOf(5), c[1].toBigInteger());
        assertEquals(BigInteger.valueOf(5), c[2].toBigInteger());
        assertEquals(BigInteger.valueOf(3), c[3].toBigInteger());
    }

    @Test
    void polyMul_random_matchesNaive() {
        var a = randomPoly(5);
        var b = randomPoly(4);
        var fftResult = FieldFFT.polyMul(a, b);
        var naiveResult = naivePolyMul(a, b);

        assertEquals(naiveResult.length, fftResult.length);
        for (int i = 0; i < naiveResult.length; i++) {
            assertEquals(naiveResult[i].toBigInteger(), fftResult[i].toBigInteger(),
                    "Coefficient " + i + " mismatch");
        }
    }

    @Test
    void polyMul_random_larger_matchesNaive() {
        var a = randomPoly(17);
        var b = randomPoly(13);
        var fftResult = FieldFFT.polyMul(a, b);
        var naiveResult = naivePolyMul(a, b);

        assertEquals(naiveResult.length, fftResult.length);
        for (int i = 0; i < naiveResult.length; i++) {
            assertEquals(naiveResult[i].toBigInteger(), fftResult[i].toBigInteger(),
                    "Coefficient " + i + " mismatch");
        }
    }

    @Test
    void polyMul_byZero() {
        var a = randomPoly(4);
        var b = new MontFr254[]{MontFr254.ZERO};
        var c = FieldFFT.polyMul(a, b);
        for (var coeff : c) assertTrue(coeff.isZero());
    }

    @Test
    void polyMul_byOne() {
        var a = new MontFr254[]{MontFr254.fromLong(5), MontFr254.fromLong(3), MontFr254.fromLong(7)};
        var b = new MontFr254[]{MontFr254.ONE};
        var c = FieldFFT.polyMul(a, b);
        assertEquals(a.length, c.length);
        for (int i = 0; i < a.length; i++) {
            assertEquals(a[i].toBigInteger(), c[i].toBigInteger());
        }
    }

    // --- Polynomial evaluation ---

    @Test
    void polyEval_constant() {
        var coeffs = new MontFr254[]{MontFr254.fromLong(42)};
        assertEquals(BigInteger.valueOf(42), FieldFFT.polyEval(coeffs, MontFr254.fromLong(999)).toBigInteger());
    }

    @Test
    void polyEval_linear() {
        // p(x) = 3 + 5x, p(2) = 13
        var coeffs = new MontFr254[]{MontFr254.fromLong(3), MontFr254.fromLong(5)};
        assertEquals(BigInteger.valueOf(13), FieldFFT.polyEval(coeffs, MontFr254.fromLong(2)).toBigInteger());
    }

    @Test
    void polyEval_atZero() {
        var coeffs = new MontFr254[]{MontFr254.fromLong(7), MontFr254.fromLong(11), MontFr254.fromLong(13)};
        assertEquals(BigInteger.valueOf(7), FieldFFT.polyEval(coeffs, MontFr254.ZERO).toBigInteger());
    }

    @Test
    void polyEval_empty() {
        assertTrue(FieldFFT.polyEval(new MontFr254[0], MontFr254.fromLong(5)).isZero());
    }

    // --- Edge cases ---

    @Test
    void fft_nonPowerOf2_throws() {
        assertThrows(IllegalArgumentException.class,
                () -> FieldFFT.fft(new MontFr254[3]));
    }

    @Test
    void padToPow2_alreadyPow2() {
        var arr = new MontFr254[]{MontFr254.ONE, MontFr254.ZERO};
        assertSame(arr, FieldFFT.padToPow2(arr));
    }

    @Test
    void padToPow2_padsCorrectly() {
        var arr = new MontFr254[]{MontFr254.fromLong(1), MontFr254.fromLong(2), MontFr254.fromLong(3)};
        var padded = FieldFFT.padToPow2(arr);
        assertEquals(4, padded.length);
        assertEquals(BigInteger.valueOf(1), padded[0].toBigInteger());
        assertEquals(BigInteger.valueOf(2), padded[1].toBigInteger());
        assertEquals(BigInteger.valueOf(3), padded[2].toBigInteger());
        assertTrue(padded[3].isZero());
    }

    // --- Larger FFT correctness ---

    @Test
    void fft_size4096_roundTrip() {
        var coeffs = randomPoly(4096);
        assertArrayEqualsFr(coeffs, FieldFFT.ifft(FieldFFT.fft(coeffs)));
    }

    // --- Helpers ---

    private MontFr254[] randomPoly(int n) {
        var coeffs = new MontFr254[n];
        for (int i = 0; i < n; i++) {
            byte[] bytes = new byte[32];
            RNG.nextBytes(bytes);
            coeffs[i] = MontFr254.fromBigInteger(new BigInteger(1, bytes).mod(R));
        }
        return coeffs;
    }

    private static MontFr254[] naivePolyMul(MontFr254[] a, MontFr254[] b) {
        int n = a.length + b.length - 1;
        MontFr254[] result = new MontFr254[n];
        for (int i = 0; i < n; i++) result[i] = MontFr254.ZERO;
        for (int i = 0; i < a.length; i++) {
            for (int j = 0; j < b.length; j++) {
                result[i + j] = result[i + j].add(a[i].mul(b[j]));
            }
        }
        return result;
    }

    private static void assertArrayEqualsFr(MontFr254[] expected, MontFr254[] actual) {
        assertEquals(expected.length, actual.length, "Array lengths differ");
        for (int i = 0; i < expected.length; i++) {
            assertEquals(expected[i].toBigInteger(), actual[i].toBigInteger(),
                    "Element " + i + " differs");
        }
    }
}
