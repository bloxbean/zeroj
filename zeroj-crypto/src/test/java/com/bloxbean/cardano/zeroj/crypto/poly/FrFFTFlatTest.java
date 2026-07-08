package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * ADR-0029 M2c: the flat {@link FrFFTFlat} NTT must compute the same transform as the object-based
 * {@link FieldFFTBLS381}, and round-trip (ifft∘fft = id), over random inputs at several sizes.
 */
class FrFFTFlatTest {

    private static final BigInteger R = MontFr381.modulus();
    private static final Random RND = new Random(0xF7ACL);

    private static MontFr381[] randomCoeffs(int n) {
        MontFr381[] c = new MontFr381[n];
        for (int i = 0; i < n; i++) c[i] = MontFr381.fromBigInteger(new BigInteger(255, RND).mod(R));
        return c;
    }

    private static long[] toFlat(MontFr381[] c) {
        long[] flat = new long[c.length * 4];
        for (int i = 0; i < c.length; i++) System.arraycopy(c[i].toLimbs(), 0, flat, i * 4, 4);
        return flat;
    }

    private static void assertMatches(MontFr381[] expected, long[] flat) {
        for (int i = 0; i < expected.length; i++) {
            long[] e = expected[i].toLimbs();
            long[] got = new long[]{flat[i * 4], flat[i * 4 + 1], flat[i * 4 + 2], flat[i * 4 + 3]};
            assertArrayEquals(e, got, "element " + i);
        }
    }

    @Test
    void fft_matchesObjectFFT() {
        for (int logN = 1; logN <= 10; logN++) {
            int n = 1 << logN;
            MontFr381[] coeffs = randomCoeffs(n);
            MontFr381[] expected = FieldFFTBLS381.fft(coeffs);
            long[] flat = toFlat(coeffs);
            FrFFTFlat.fft(flat, n);
            assertMatches(expected, flat);
        }
    }

    @Test
    void ifft_matchesObjectFFT() {
        for (int logN = 1; logN <= 10; logN++) {
            int n = 1 << logN;
            MontFr381[] evals = randomCoeffs(n);
            MontFr381[] expected = FieldFFTBLS381.ifft(evals);
            long[] flat = toFlat(evals);
            FrFFTFlat.ifft(flat, n);
            assertMatches(expected, flat);
        }
    }

    @Test
    void ifftOfFft_isIdentity() {
        int n = 256;
        MontFr381[] coeffs = randomCoeffs(n);
        long[] flat = toFlat(coeffs);
        FrFFTFlat.fft(flat, n);
        FrFFTFlat.ifft(flat, n);
        assertMatches(coeffs, flat);
    }

    /** ADR-0029 M5b: above PAR_MIN (2¹⁶) the multi-core path engages — must match the oracle too. */
    @Test
    void parallelFft_aboveThreshold_matchesObjectFFT() {
        int n = 1 << 17;
        MontFr381[] coeffs = randomCoeffs(n);
        MontFr381[] expected = FieldFFTBLS381.fft(coeffs);
        long[] flat = toFlat(coeffs);
        FrFFTFlat.fft(flat, n);
        assertMatches(expected, flat);
        FrFFTFlat.ifft(flat, n);
        assertMatches(coeffs, flat); // and round-trips
    }

    /** {@link FrFFTFlat#pow} must match BigInteger modPow (spot exponents incl. 0 and 1). */
    @Test
    void pow_matchesModPow() {
        MontFr381 base = MontFr381.fromBigInteger(new BigInteger(255, RND).mod(R));
        for (int e : new int[]{0, 1, 2, 3, 7, 100, 65535, 1 << 20}) {
            long[] out = new long[4];
            FrFFTFlat.pow(out, base.toLimbs(), e);
            MontFr381 expected = MontFr381.fromBigInteger(base.toBigInteger().modPow(BigInteger.valueOf(e), R));
            assertArrayEquals(expected.toLimbs(), out, "base^" + e);
        }
    }
}
