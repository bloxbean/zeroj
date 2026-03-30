package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.crypto.field.MontFr254;

import java.math.BigInteger;

/**
 * Number Theoretic Transform (NTT) over the BN254 scalar field Fr.
 *
 * <p>Implements radix-2 Cooley-Tukey FFT for polynomial evaluation and interpolation
 * over prime fields. This is the core algorithm needed for:</p>
 * <ul>
 *   <li>Groth16: computing h(x) = (A(x)*B(x) - C(x)) / Z_H(x)</li>
 *   <li>PlonK: polynomial multiplication and division for quotient polynomial</li>
 *   <li>KZG: polynomial evaluation at multiple points</li>
 * </ul>
 *
 * <h3>BN254 Fr 2-adicity</h3>
 * <p>The BN254 scalar field r satisfies r-1 = 2^28 * t (2-adicity = 28),
 * so FFT domains up to 2^28 = 268M elements are supported. This is sufficient
 * for circuits up to ~268M constraints.</p>
 *
 * <h3>Performance</h3>
 * <p>O(n log n) field multiplications. For n=2^16 (65536), approximately
 * 16 * 65536 = ~1M multiplications.</p>
 */
public final class FieldFFT {

    private FieldFFT() {}

    /** Maximum supported domain exponent (2-adicity of BN254 Fr). */
    public static final int MAX_LOG_DOMAIN = 28;

    /** BN254 Fr modulus. */
    private static final BigInteger R = MontFr254.modulus();

    /**
     * Primitive 2^28-th root of unity in BN254 Fr.
     * omega^(2^28) = 1 and omega^(2^27) = -1.
     */
    private static final MontFr254 ROOT_OF_UNITY = MontFr254.fromBigInteger(
            new BigInteger("19103219067921713944291392827692070036145651957329286315305642004821462161904"));

    /**
     * Compute the primitive n-th root of unity where n = 2^logN.
     *
     * @param logN log2 of the domain size (must be in [1, 28])
     * @return omega such that omega^n = 1 and omega^(n/2) = -1
     */
    public static MontFr254 rootOfUnity(int logN) {
        if (logN < 1 || logN > MAX_LOG_DOMAIN)
            throw new IllegalArgumentException("logN must be in [1, " + MAX_LOG_DOMAIN + "], got " + logN);
        // omega_logN = ROOT_OF_UNITY^(2^(28 - logN))
        MontFr254 omega = ROOT_OF_UNITY;
        for (int i = MAX_LOG_DOMAIN; i > logN; i--) {
            omega = omega.square();
        }
        return omega;
    }

    /**
     * Forward NTT: coefficients -> evaluations.
     *
     * <p>Given polynomial coefficients [a_0, a_1, ..., a_{n-1}],
     * returns [p(omega^0), p(omega^1), ..., p(omega^{n-1})]
     * where omega is the primitive n-th root of unity.</p>
     *
     * @param coeffs polynomial coefficients (length must be a power of 2)
     * @return evaluations at powers of omega
     */
    public static MontFr254[] fft(MontFr254[] coeffs) {
        int n = coeffs.length;
        int logN = Integer.numberOfTrailingZeros(n);
        if (n != (1 << logN))
            throw new IllegalArgumentException("Length must be a power of 2, got " + n);
        if (logN > MAX_LOG_DOMAIN)
            throw new IllegalArgumentException("Domain too large: 2^" + logN + " > 2^" + MAX_LOG_DOMAIN);

        MontFr254 omega = rootOfUnity(logN);
        MontFr254[] result = coeffs.clone();
        fftInPlace(result, omega);
        return result;
    }

    /**
     * Inverse NTT: evaluations -> coefficients.
     *
     * <p>Given evaluations [p(omega^0), ..., p(omega^{n-1})],
     * returns the polynomial coefficients [a_0, ..., a_{n-1}].</p>
     *
     * <p>This is FFT with omega^{-1} followed by division by n.</p>
     *
     * @param evals evaluations at powers of omega (length must be a power of 2)
     * @return polynomial coefficients
     */
    public static MontFr254[] ifft(MontFr254[] evals) {
        int n = evals.length;
        int logN = Integer.numberOfTrailingZeros(n);
        if (n != (1 << logN))
            throw new IllegalArgumentException("Length must be a power of 2, got " + n);
        if (logN > MAX_LOG_DOMAIN)
            throw new IllegalArgumentException("Domain too large: 2^" + logN + " > 2^" + MAX_LOG_DOMAIN);

        MontFr254 omega = rootOfUnity(logN);
        MontFr254 omegaInv = omega.inverse();
        MontFr254 nInv = MontFr254.fromLong(n).inverse();

        MontFr254[] result = evals.clone();
        fftInPlace(result, omegaInv);

        // Divide every element by n
        for (int i = 0; i < n; i++) {
            result[i] = result[i].mul(nInv);
        }
        return result;
    }

    /**
     * In-place radix-2 Cooley-Tukey NTT.
     *
     * <p>Standard iterative decimation-in-time butterfly algorithm.
     * Bit-reversal permutation first, then log(n) rounds of butterflies.</p>
     */
    private static void fftInPlace(MontFr254[] a, MontFr254 omega) {
        int n = a.length;
        int logN = Integer.numberOfTrailingZeros(n);

        // Bit-reversal permutation
        for (int i = 0; i < n; i++) {
            int j = bitReverse(i, logN);
            if (i < j) {
                var tmp = a[i];
                a[i] = a[j];
                a[j] = tmp;
            }
        }

        // Butterfly rounds
        for (int s = 1; s <= logN; s++) {
            int m = 1 << s;         // current block size
            int half = m >> 1;

            // omega_m = omega^(n/m) = primitive m-th root of unity
            MontFr254 omegaM = omega;
            for (int i = logN; i > s; i--) {
                omegaM = omegaM.square();
            }

            for (int k = 0; k < n; k += m) {
                MontFr254 w = MontFr254.ONE;
                for (int j = 0; j < half; j++) {
                    MontFr254 t = w.mul(a[k + j + half]);
                    MontFr254 u = a[k + j];
                    a[k + j] = u.add(t);
                    a[k + j + half] = u.sub(t);
                    w = w.mul(omegaM);
                }
            }
        }
    }

    /**
     * Pad a coefficient array to the next power of 2.
     *
     * @param coeffs input coefficients
     * @return padded array (same array if already power of 2)
     */
    public static MontFr254[] padToPow2(MontFr254[] coeffs) {
        int n = coeffs.length;
        if (n == 0) return new MontFr254[]{MontFr254.ZERO};
        if ((n & (n - 1)) == 0) return coeffs; // already power of 2

        int next = Integer.highestOneBit(n) << 1;
        MontFr254[] padded = new MontFr254[next];
        System.arraycopy(coeffs, 0, padded, 0, n);
        for (int i = n; i < next; i++) {
            padded[i] = MontFr254.ZERO;
        }
        return padded;
    }

    /**
     * Multiply two polynomials using FFT.
     *
     * <p>Given polynomials A(x) and B(x) as coefficient arrays,
     * returns C(x) = A(x) * B(x) using the convolution theorem:
     * FFT(C) = FFT(A) * FFT(B), then C = IFFT(FFT(C)).</p>
     *
     * @return product polynomial coefficients
     */
    public static MontFr254[] polyMul(MontFr254[] a, MontFr254[] b) {
        int resultLen = a.length + b.length - 1;

        // Handle degree-0 polynomials (single coefficient) — no FFT needed
        if (resultLen <= 1) {
            MontFr254 product = (a.length > 0 && b.length > 0) ? a[0].mul(b[0]) : MontFr254.ZERO;
            return new MontFr254[]{product};
        }
        if (a.length == 1) {
            // Scalar * polynomial — direct multiply
            MontFr254[] result = new MontFr254[b.length];
            for (int i = 0; i < b.length; i++) result[i] = a[0].mul(b[i]);
            return result;
        }
        if (b.length == 1) {
            // Polynomial * scalar — direct multiply
            MontFr254[] result = new MontFr254[a.length];
            for (int i = 0; i < a.length; i++) result[i] = b[0].mul(a[i]);
            return result;
        }

        int n = Integer.highestOneBit(resultLen - 1) << 1; // next power of 2
        if (n < resultLen) n = Integer.highestOneBit(resultLen) << 1;
        if ((resultLen & (resultLen - 1)) == 0) n = resultLen; // exact power of 2

        // Pad both to size n
        MontFr254[] pa = new MontFr254[n];
        MontFr254[] pb = new MontFr254[n];
        System.arraycopy(a, 0, pa, 0, a.length);
        System.arraycopy(b, 0, pb, 0, b.length);
        for (int i = a.length; i < n; i++) pa[i] = MontFr254.ZERO;
        for (int i = b.length; i < n; i++) pb[i] = MontFr254.ZERO;

        // FFT both
        var fa = fft(pa);
        var fb = fft(pb);

        // Pointwise multiply
        MontFr254[] fc = new MontFr254[n];
        for (int i = 0; i < n; i++) {
            fc[i] = fa[i].mul(fb[i]);
        }

        // IFFT
        var result = ifft(fc);

        // Trim to actual degree
        MontFr254[] trimmed = new MontFr254[resultLen];
        System.arraycopy(result, 0, trimmed, 0, resultLen);
        return trimmed;
    }

    /**
     * Evaluate a polynomial at a specific point using Horner's method.
     *
     * @param coeffs polynomial coefficients [a_0, a_1, ..., a_n]
     * @param point the evaluation point
     * @return a_0 + a_1*point + a_2*point^2 + ...
     */
    public static MontFr254 polyEval(MontFr254[] coeffs, MontFr254 point) {
        if (coeffs.length == 0) return MontFr254.ZERO;
        MontFr254 result = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 2; i >= 0; i--) {
            result = result.mul(point).add(coeffs[i]);
        }
        return result;
    }

    // --- Bit reversal ---

    private static int bitReverse(int x, int logN) {
        int result = 0;
        for (int i = 0; i < logN; i++) {
            result = (result << 1) | (x & 1);
            x >>= 1;
        }
        return result;
    }
}
