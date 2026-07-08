package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.bls12381.field.FrArith381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

import java.util.stream.IntStream;

/**
 * Allocation-lean radix-2 NTT over flat {@code long[]} storage (ADR-0029 M2c), multi-core for large
 * transforms (M5b).
 *
 * <p>Operates in place on {@code n} Fr elements packed as {@code n·4} Montgomery longs, using
 * {@link FrArith381} with reused scratch — no per-butterfly {@link MontFr381} object allocation
 * (the transient FFT arrays are the prover's remaining on-heap memory driver after the key went
 * off-heap in M4). Byte-for-byte the same transform as {@link FieldFFTBLS381}; validated against it
 * in {@code FrFFTFlatTest}.</p>
 *
 * <p>M5b: profiling the real 2²⁵-domain derivation prove showed the NTT running single-threaded for
 * ~3 min once the MSMs were parallelized. Butterflies within a stage are independent, so each stage
 * fans out across cores — over blocks while blocks are plentiful, over the inner twiddle walk (with
 * per-chunk starting powers {@code omegaM^jLo}) once blocks get large. Same field ops in the same
 * pairs ⇒ bit-identical results. Transforms below {@link #PAR_MIN} keep the serial path.</p>
 */
public final class FrFFTFlat {

    private FrFFTFlat() {}

    private static final int L = FrArith381.LIMBS; // 4
    private static final long[] FR_ONE = MontFr381.ONE.toLimbs();

    /** Below this size the fan-out overhead outweighs the win — run serial. */
    private static final int PAR_MIN = 1 << 16;

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
        if (n < PAR_MIN) {
            for (int i = 0; i < n; i++) FrArith381.mul(a, i * L, a, i * L, nInv, 0);
        } else {
            parallelRange(n, (lo, hi) -> {
                for (int i = lo; i < hi; i++) FrArith381.mul(a, i * L, a, i * L, nInv, 0);
            });
        }
    }

    /** In-place NTT with an explicit flat primitive n-th root {@code omega}. */
    public static void fftInPlaceOmega(long[] a, int n, long[] omega) {
        int logN = Integer.numberOfTrailingZeros(n);
        if (n < PAR_MIN) { fftSerial(a, n, logN, omega); return; }

        // bit-reversal permutation — each i<j pair is swapped exactly once, pairs are disjoint
        parallelRange(n, (lo, hi) -> {
            long[] tmp = new long[L];
            for (int i = lo; i < hi; i++) {
                int j = bitReverse(i, logN);
                if (i < j) {
                    System.arraycopy(a, i * L, tmp, 0, L);
                    System.arraycopy(a, j * L, a, i * L, L);
                    System.arraycopy(tmp, 0, a, j * L, L);
                }
            }
        });

        int cores = Runtime.getRuntime().availableProcessors();
        long[] omegaM = new long[L];
        for (int s = 1; s <= logN; s++) {
            int m = 1 << s, half = m >> 1;

            // omegaM = omega^(2^(logN-s))
            System.arraycopy(omega, 0, omegaM, 0, L);
            for (int i = logN; i > s; i--) FrArith381.sqr(omegaM, 0, omegaM, 0);
            long[] om = omegaM.clone(); // capture-stable for the lambdas

            int numBlocks = n / m;
            if (numBlocks >= cores) {
                // plenty of blocks: fan blocks across cores, each walks its own twiddle from 1
                parallelRange(numBlocks, (bLo, bHi) -> {
                    long[] t = new long[L], u = new long[L], w = new long[L];
                    for (int b = bLo; b < bHi; b++) {
                        int k = b * m;
                        System.arraycopy(FR_ONE, 0, w, 0, L);
                        for (int j = 0; j < half; j++) {
                            butterfly(a, k + j, k + j + half, w, t, u);
                            FrArith381.mul(w, 0, w, 0, om, 0);
                        }
                    }
                });
            } else {
                // few large blocks: fan the inner twiddle walk, chunk c starts at omegaM^jLo
                for (int k = 0; k < n; k += m) {
                    final int kf = k;
                    parallelRange(half, (jLo, jHi) -> {
                        long[] t = new long[L], u = new long[L], w = new long[L];
                        pow(w, om, jLo);
                        for (int j = jLo; j < jHi; j++) {
                            butterfly(a, kf + j, kf + j + half, w, t, u);
                            FrArith381.mul(w, 0, w, 0, om, 0);
                        }
                    });
                }
            }
        }
    }

    /** {@code out = base^exp} in Montgomery form (square-and-multiply; {@code exp >= 0}). */
    public static void pow(long[] out, long[] base, int exp) {
        long[] acc = FR_ONE.clone(), b = base.clone();
        while (exp > 0) {
            if ((exp & 1) == 1) FrArith381.mul(acc, 0, acc, 0, b, 0);
            FrArith381.sqr(b, 0, b, 0);
            exp >>>= 1;
        }
        System.arraycopy(acc, 0, out, 0, L);
    }

    /** Split {@code [0, n)} into one contiguous chunk per core and run them concurrently. */
    public static void parallelRange(int n, RangeBody body) {
        int t = Math.min(Runtime.getRuntime().availableProcessors(), Math.max(1, n));
        int per = (n + t - 1) / t;
        IntStream.range(0, t).parallel().forEach(c -> {
            int lo = c * per, hi = Math.min(n, lo + per);
            if (lo < hi) body.run(lo, hi);
        });
    }

    /** A body applied to the index range {@code [lo, hi)}. */
    public interface RangeBody { void run(int lo, int hi); }

    private static void butterfly(long[] a, int loIdx, int hiIdx, long[] w, long[] t, long[] u) {
        int lo = loIdx * L, hi = hiIdx * L;
        FrArith381.mul(t, 0, w, 0, a, hi);      // t = w · a[hi]
        System.arraycopy(a, lo, u, 0, L);       // u = a[lo]
        FrArith381.add(a, lo, u, 0, t, 0);      // a[lo] = u + t
        FrArith381.sub(a, hi, u, 0, t, 0);      // a[hi] = u - t
    }

    private static void fftSerial(long[] a, int n, int logN, long[] omega) {
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
            System.arraycopy(omega, 0, omegaM, 0, L);
            for (int i = logN; i > s; i--) FrArith381.sqr(omegaM, 0, omegaM, 0);
            for (int k = 0; k < n; k += m) {
                System.arraycopy(FR_ONE, 0, w, 0, L);
                for (int j = 0; j < half; j++) {
                    butterfly(a, k + j, k + j + half, w, t, u);
                    FrArith381.mul(w, 0, w, 0, omegaM, 0);
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
