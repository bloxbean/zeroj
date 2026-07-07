package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

/**
 * Allocation-lean radix-2 NTT over flat {@code long[]} storage (ADR-0029 M2c).
 *
 * <p>Operates in place on {@code n} Fr elements packed as {@code n·4} Montgomery longs, using
 * {@link FrArith381} with reused scratch — no per-butterfly {@link MontFr381} object allocation
 * (the transient FFT arrays are the prover's remaining on-heap memory driver after the key went
 * off-heap in M4). Byte-for-byte the same transform as {@link FieldFFTBLS381}; validated against it
 * in {@code FrFFTFlatTest}.</p>
 */
public final class FrFFTFlat {

    private FrFFTFlat() {}

    private static final int L = FrArith381.LIMBS; // 4
    private static final long[] FR_ONE = MontFr381.ONE.toLimbs();

    /** Forward NTT of {@code n} flat Fr coefficients (in place). */
    public static void fft(long[] a, int n) {
        fftInPlaceOmega(a, n, FieldFFTBLS381.rootOfUnity(Integer.numberOfTrailingZeros(n)).toLimbs());
    }

    /** Inverse NTT of {@code n} flat Fr evaluations (in place), scaled by 1/n. */
    public static void ifft(long[] a, int n) {
        int logN = Integer.numberOfTrailingZeros(n);
        long[] omegaInv = FieldFFTBLS381.rootOfUnity(logN).inverse().toLimbs();
        fftInPlaceOmega(a, n, omegaInv);
        long[] nInv = MontFr381.fromLong(n).inverse().toLimbs();
        for (int i = 0; i < n; i++) FrArith381.mul(a, i * L, a, i * L, nInv, 0);
    }

    /** In-place NTT with an explicit flat primitive n-th root {@code omega}. */
    public static void fftInPlaceOmega(long[] a, int n, long[] omega) {
        int logN = Integer.numberOfTrailingZeros(n);

        // bit-reversal permutation (swap 4-long groups)
        long[] tmp = new long[L];
        for (int i = 0; i < n; i++) {
            int j = bitReverse(i, logN);
            if (i < j) {
                System.arraycopy(a, i * L, tmp, 0, L);
                System.arraycopy(a, j * L, a, i * L, L);
                System.arraycopy(tmp, 0, a, j * L, L);
            }
        }

        long[] t = new long[L], u = new long[L], w = new long[L], omegaM = new long[L];
        for (int s = 1; s <= logN; s++) {
            int m = 1 << s, half = m >> 1;

            // omegaM = omega^(2^(logN-s))
            System.arraycopy(omega, 0, omegaM, 0, L);
            for (int i = logN; i > s; i--) FrArith381.sqr(omegaM, 0, omegaM, 0);

            for (int k = 0; k < n; k += m) {
                System.arraycopy(FR_ONE, 0, w, 0, L);
                for (int j = 0; j < half; j++) {
                    int lo = (k + j) * L, hi = (k + j + half) * L;
                    FrArith381.mul(t, 0, w, 0, a, hi);      // t = w · a[hi]
                    System.arraycopy(a, lo, u, 0, L);       // u = a[lo]
                    FrArith381.add(a, lo, u, 0, t, 0);      // a[lo] = u + t
                    FrArith381.sub(a, hi, u, 0, t, 0);      // a[hi] = u - t
                    FrArith381.mul(w, 0, w, 0, omegaM, 0);  // w *= omegaM
                }
            }
        }
    }

    private static int bitReverse(int x, int logN) {
        int result = 0;
        for (int i = 0; i < logN; i++) {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        return result;
    }
}
