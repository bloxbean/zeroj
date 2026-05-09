package com.bloxbean.cardano.zeroj.crypto.poly;

import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;

/**
 * Number Theoretic Transform (NTT) over the BLS12-381 scalar field Fr.
 *
 * <p>BLS12-381 Fr 2-adicity: r-1 = 2^32 * t, supporting FFT domains up to 2^32.</p>
 *
 * @see FieldFFT
 */
public final class FieldFFTBLS381 {

    private FieldFFTBLS381() {}

    /** Maximum supported domain exponent (2-adicity of BLS12-381 Fr). */
    public static final int MAX_LOG_DOMAIN = 32;

    /**
     * Primitive 2^32-th root of unity in BLS12-381 Fr.
     * omega^(2^32) = 1 and omega^(2^31) != 1.
     */
    private static final MontFr381 ROOT_OF_UNITY = MontFr381.fromBigInteger(
            new BigInteger("937917089079007706106976984802249742464848817460758522850752807661925904159"));

    /**
     * Compute the primitive n-th root of unity where n = 2^logN.
     */
    public static MontFr381 rootOfUnity(int logN) {
        if (logN < 1 || logN > MAX_LOG_DOMAIN)
            throw new IllegalArgumentException("logN must be in [1, " + MAX_LOG_DOMAIN + "], got " + logN);
        MontFr381 omega = ROOT_OF_UNITY;
        for (int i = MAX_LOG_DOMAIN; i > logN; i--) {
            omega = omega.square();
        }
        return omega;
    }

    /** Forward NTT: coefficients -> evaluations. */
    public static MontFr381[] fft(MontFr381[] coeffs) {
        int n = coeffs.length;
        int logN = Integer.numberOfTrailingZeros(n);
        if (n != (1 << logN))
            throw new IllegalArgumentException("Length must be a power of 2, got " + n);
        if (logN > MAX_LOG_DOMAIN)
            throw new IllegalArgumentException("Domain too large: 2^" + logN + " > 2^" + MAX_LOG_DOMAIN);

        MontFr381 omega = rootOfUnity(logN);
        MontFr381[] result = coeffs.clone();
        fftInPlace(result, omega);
        return result;
    }

    /** Inverse NTT: evaluations -> coefficients. */
    public static MontFr381[] ifft(MontFr381[] evals) {
        int n = evals.length;
        int logN = Integer.numberOfTrailingZeros(n);
        if (n != (1 << logN))
            throw new IllegalArgumentException("Length must be a power of 2, got " + n);
        if (logN > MAX_LOG_DOMAIN)
            throw new IllegalArgumentException("Domain too large: 2^" + logN + " > 2^" + MAX_LOG_DOMAIN);

        MontFr381 omega = rootOfUnity(logN);
        MontFr381 omegaInv = omega.inverse();
        MontFr381 nInv = MontFr381.fromLong(n).inverse();

        MontFr381[] result = evals.clone();
        fftInPlace(result, omegaInv);

        for (int i = 0; i < n; i++) {
            result[i] = result[i].mul(nInv);
        }
        return result;
    }

    private static void fftInPlace(MontFr381[] a, MontFr381 omega) {
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
            int m = 1 << s;
            int half = m >> 1;

            MontFr381 omegaM = omega;
            for (int i = logN; i > s; i--) {
                omegaM = omegaM.square();
            }

            for (int k = 0; k < n; k += m) {
                MontFr381 w = MontFr381.ONE;
                for (int j = 0; j < half; j++) {
                    MontFr381 t = w.mul(a[k + j + half]);
                    MontFr381 u = a[k + j];
                    a[k + j] = u.add(t);
                    a[k + j + half] = u.sub(t);
                    w = w.mul(omegaM);
                }
            }
        }
    }

    /** Pad to next power of 2. */
    public static MontFr381[] padToPow2(MontFr381[] coeffs) {
        int n = coeffs.length;
        if (n == 0) return new MontFr381[]{MontFr381.ZERO};
        if ((n & (n - 1)) == 0) return coeffs;

        int next = Integer.highestOneBit(n) << 1;
        MontFr381[] padded = new MontFr381[next];
        System.arraycopy(coeffs, 0, padded, 0, n);
        for (int i = n; i < next; i++) {
            padded[i] = MontFr381.ZERO;
        }
        return padded;
    }

    /** FFT-based polynomial multiplication. */
    public static MontFr381[] polyMul(MontFr381[] a, MontFr381[] b) {
        int resultLen = a.length + b.length - 1;

        if (resultLen <= 1) {
            MontFr381 product = (a.length > 0 && b.length > 0) ? a[0].mul(b[0]) : MontFr381.ZERO;
            return new MontFr381[]{product};
        }
        if (a.length == 1) {
            MontFr381[] result = new MontFr381[b.length];
            for (int i = 0; i < b.length; i++) result[i] = a[0].mul(b[i]);
            return result;
        }
        if (b.length == 1) {
            MontFr381[] result = new MontFr381[a.length];
            for (int i = 0; i < a.length; i++) result[i] = b[0].mul(a[i]);
            return result;
        }

        int n = Integer.highestOneBit(resultLen - 1) << 1;
        if (n < resultLen) n = Integer.highestOneBit(resultLen) << 1;
        if ((resultLen & (resultLen - 1)) == 0) n = resultLen;

        MontFr381[] pa = new MontFr381[n];
        MontFr381[] pb = new MontFr381[n];
        System.arraycopy(a, 0, pa, 0, a.length);
        System.arraycopy(b, 0, pb, 0, b.length);
        for (int i = a.length; i < n; i++) pa[i] = MontFr381.ZERO;
        for (int i = b.length; i < n; i++) pb[i] = MontFr381.ZERO;

        var fa = fft(pa);
        var fb = fft(pb);

        MontFr381[] fc = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            fc[i] = fa[i].mul(fb[i]);
        }

        var result = ifft(fc);

        MontFr381[] trimmed = new MontFr381[resultLen];
        System.arraycopy(result, 0, trimmed, 0, resultLen);
        return trimmed;
    }

    /** Evaluate polynomial at a point using Horner's method. */
    public static MontFr381 polyEval(MontFr381[] coeffs, MontFr381 point) {
        if (coeffs.length == 0) return MontFr381.ZERO;
        MontFr381 result = coeffs[coeffs.length - 1];
        for (int i = coeffs.length - 2; i >= 0; i--) {
            result = result.mul(point).add(coeffs[i]);
        }
        return result;
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
