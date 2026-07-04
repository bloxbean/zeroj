package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;

import java.math.BigInteger;

/**
 * Pippenger's algorithm for multi-scalar multiplication (MSM) on BLS12-381 G1.
 *
 * <p>Computes sum(s_i * P_i) for n scalars and n points.</p>
 *
 * @see Pippenger
 */
public final class PippengerBLS381 {

    private PippengerBLS381() {}

    private static final int SCALAR_BITS = 255; // BLS12-381 Fr bit length

    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    public static JacobianG1BLS381 msm(AffineG1[] points, BigInteger[] scalars) {
        if (points.length != scalars.length)
            throw new IllegalArgumentException("points and scalars must have the same length");
        int n = points.length;
        if (n == 0) return JacobianG1BLS381.INFINITY;

        scalars = scalars.clone();
        for (int i = 0; i < n; i++) {
            if (scalars[i].signum() < 0 || scalars[i].compareTo(FR) >= 0) {
                scalars[i] = scalars[i].mod(FR);
            }
        }
        if (n == 1) return JacobianG1BLS381.fromAffine(points[0].x(), points[0].y()).scalarMul(scalars[0]);

        int c = windowSize(n);
        int numBuckets = (1 << c) - 1;
        int numWindows = (SCALAR_BITS + c - 1) / c;

        JacobianG1BLS381 result = JacobianG1BLS381.INFINITY;

        for (int w = numWindows - 1; w >= 0; w--) {
            if (!result.isInfinity()) {
                for (int d = 0; d < c; d++) {
                    result = result.doublePoint();
                }
            }

            JacobianG1BLS381[] buckets = new JacobianG1BLS381[numBuckets + 1];
            for (int i = 0; i <= numBuckets; i++) {
                buckets[i] = JacobianG1BLS381.INFINITY;
            }

            int bitOffset = w * c;
            for (int i = 0; i < n; i++) {
                int digit = extractWindow(scalars[i], bitOffset, c);
                if (digit != 0) {
                    if (points[i].isInfinity()) continue;
                    buckets[digit] = buckets[digit].addAffine(points[i].x(), points[i].y());
                }
            }

            JacobianG1BLS381 runningSum = JacobianG1BLS381.INFINITY;
            JacobianG1BLS381 windowSum = JacobianG1BLS381.INFINITY;

            for (int j = numBuckets; j >= 1; j--) {
                runningSum = runningSum.add(buckets[j]);
                windowSum = windowSum.add(runningSum);
            }

            result = result.add(windowSum);
        }

        return result;
    }

    public static JacobianG1BLS381 naiveMsm(AffineG1[] points, BigInteger[] scalars) {
        JacobianG1BLS381 result = JacobianG1BLS381.INFINITY;
        for (int i = 0; i < points.length; i++) {
            if (scalars[i].signum() != 0 && !points[i].isInfinity()) {
                result = result.add(
                        JacobianG1BLS381.fromAffine(points[i].x(), points[i].y()).scalarMul(scalars[i]));
            }
        }
        return result;
    }

    static int windowSize(int n) {
        if (n <= 4) return 3;
        int logN = 31 - Integer.numberOfLeadingZeros(n);
        return Math.max(3, Math.min(logN, 16));
    }

    private static int extractWindow(BigInteger scalar, int bitOffset, int windowBits) {
        int digit = 0;
        for (int b = 0; b < windowBits; b++) {
            int bitPos = bitOffset + b;
            if (bitPos < scalar.bitLength() && scalar.testBit(bitPos)) {
                digit |= (1 << b);
            }
        }
        return digit;
    }
}
