package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianArith381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;

import java.math.BigInteger;

/**
 * Allocation-lean Pippenger MSM on BLS12-381 G1 over flat {@code long[]} storage (ADR-0029 M1c).
 *
 * <p>Same algorithm as {@link PippengerBLS381} but the buckets and accumulators are flat
 * {@code long[]} point buffers ({@link JacobianArith381}), so the hot loop does <b>no per-op object
 * allocation</b> — only a handful of arrays per MSM call (buckets + accumulators + a reused field
 * scratch), instead of the hundreds of millions of {@code MontFp381}/{@code JacobianG1BLS381} objects
 * the object path churns. Scalars are pre-decoded to little-endian bytes once, eliminating the
 * per-bit {@code BigInteger.testBit} in window extraction.</p>
 *
 * <p>Points are packed affine: point {@code i} is {@code affine[i*12 .. i*12+11]} = x[6] then y[6]
 * (Montgomery limbs); the affine point-at-infinity is {@code (0,0)}. The result is written to
 * {@code out[oo .. oo+17]} as a flat Jacobian point. Bit-identical (curve-equivalent) to
 * {@link PippengerBLS381#msm} — see {@code PippengerFlatBLS381Test}.</p>
 */
public final class PippengerFlatBLS381 {

    private PippengerFlatBLS381() {}

    private static final int SCALAR_BITS = 255;
    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private static final int PL = JacobianArith381.POINT_LONGS; // 18
    private static final int AFF = 12;                          // affine longs per point

    /** Affine longs per packed point (x[6], y[6]). */
    public static int affineStride() { return AFF; }

    /**
     * {@code out[oo..] = Σ scalars[i] · points[i]}.
     *
     * @param out    result buffer (>= oo + 18)
     * @param affine packed affine points, {@code n * 12} longs (x[6],y[6] Montgomery)
     * @param n      number of points
     * @param scalars n scalars
     */
    public static void msm(long[] out, int oo, long[] affine, int n, BigInteger[] scalars) {
        JacobianArith381.setInfinity(out, oo);
        if (n == 0) return;

        long[] s = new long[JacobianArith381.SCRATCH_LONGS];

        byte[][] sb = new byte[n][];
        for (int i = 0; i < n; i++) {
            BigInteger v = scalars[i];
            if (v.signum() < 0 || v.compareTo(FR) >= 0) v = v.mod(FR);
            sb[i] = leBytes32(v);
        }

        int c = windowSize(n);
        int numBuckets = (1 << c) - 1;
        int numWindows = (SCALAR_BITS + c - 1) / c;

        long[] buckets = new long[(numBuckets + 1) * PL];
        long[] running = new long[PL];
        long[] window = new long[PL];

        for (int w = numWindows - 1; w >= 0; w--) {
            if (!JacobianArith381.isInfinity(out, oo)) {
                for (int d = 0; d < c; d++) JacobianArith381.dbl(out, oo, out, oo, s);
            }
            for (int i = 0; i <= numBuckets; i++) JacobianArith381.setInfinity(buckets, i * PL);

            int bitOffset = w * c;
            for (int i = 0; i < n; i++) {
                int digit = extractWindow(sb[i], bitOffset, c);
                if (digit == 0) continue;
                int po = i * AFF;
                if (isAffineInfinity(affine, po)) continue;
                int bo = digit * PL;
                JacobianArith381.addAffine(buckets, bo, buckets, bo, affine, po, affine, po + 6, s);
            }

            JacobianArith381.setInfinity(running, 0);
            JacobianArith381.setInfinity(window, 0);
            for (int j = numBuckets; j >= 1; j--) {
                JacobianArith381.add(running, 0, running, 0, buckets, j * PL, s);
                JacobianArith381.add(window, 0, window, 0, running, 0, s);
            }
            JacobianArith381.add(out, oo, out, oo, window, 0, s);
        }
    }

    /**
     * Drop-in for {@link PippengerBLS381#msm}: packs {@code AffineG1[]} into flat storage, runs the
     * allocation-lean MSM, and returns the result as a {@link JacobianG1BLS381}. Same result (see
     * {@code PippengerFlatBLS381Test}), no per-op object churn in the MSM.
     */
    public static JacobianG1BLS381 msm(AffineG1[] points, BigInteger[] scalars) {
        int n = points.length;
        long[] affine = new long[n * AFF];
        for (int i = 0; i < n; i++) {
            AffineG1 p = points[i];
            if (p.isInfinity()) continue; // leave (0,0)
            System.arraycopy(p.x().toLimbs(), 0, affine, i * AFF, 6);
            System.arraycopy(p.y().toLimbs(), 0, affine, i * AFF + 6, 6);
        }
        long[] out = new long[PL];
        msm(out, 0, affine, n, scalars);
        return toJacobian(out);
    }

    /** Flat Jacobian (18 longs) → {@link JacobianG1BLS381} (via affine; one Fp inverse). */
    private static JacobianG1BLS381 toJacobian(long[] p) {
        if (JacobianArith381.isInfinity(p, 0)) return JacobianG1BLS381.INFINITY;
        MontFp381 x = MontFp381.fromMontLimbs(p[0], p[1], p[2], p[3], p[4], p[5]);
        MontFp381 y = MontFp381.fromMontLimbs(p[6], p[7], p[8], p[9], p[10], p[11]);
        MontFp381 z = MontFp381.fromMontLimbs(p[12], p[13], p[14], p[15], p[16], p[17]);
        MontFp381 zi = z.inverse(), zi2 = zi.square(), zi3 = zi2.mul(zi);
        return JacobianG1BLS381.fromAffine(x.mul(zi2), y.mul(zi3));
    }

    static int windowSize(int n) {
        if (n <= 4) return 3;
        int logN = 31 - Integer.numberOfLeadingZeros(n);
        return Math.max(3, Math.min(logN, 16));
    }

    private static boolean isAffineInfinity(long[] affine, int po) {
        for (int i = 0; i < AFF; i++) if (affine[po + i] != 0L) return false;
        return true;
    }

    private static int extractWindow(byte[] le, int bitOffset, int windowBits) {
        int digit = 0;
        for (int b = 0; b < windowBits; b++) {
            int bitPos = bitOffset + b;
            int byteIdx = bitPos >>> 3;
            if (byteIdx < le.length) {
                int bit = (le[byteIdx] >>> (bitPos & 7)) & 1;
                digit |= bit << b;
            }
        }
        return digit;
    }

    /** 32-byte little-endian encoding of a non-negative value < 2^256. */
    private static byte[] leBytes32(BigInteger v) {
        byte[] be = v.toByteArray(); // big-endian, may have a leading sign byte
        byte[] le = new byte[32];
        for (int i = 0; i < be.length && i < 32; i++) {
            le[i] = be[be.length - 1 - i];
        }
        return le;
    }
}
