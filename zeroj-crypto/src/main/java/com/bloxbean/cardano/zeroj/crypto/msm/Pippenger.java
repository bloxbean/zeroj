package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;

import java.math.BigInteger;

/**
 * Pippenger's algorithm for multi-scalar multiplication (MSM) on BN254 G1.
 *
 * <p>Computes sum(s_i * P_i) for n scalars and n points. This is the dominant
 * cost in ZK provers (Groth16, PlonK).</p>
 *
 * <h3>Algorithm overview</h3>
 * <ol>
 *   <li>Choose window size c = max(3, floor(log2(n)))</li>
 *   <li>Decompose each scalar into c-bit windows</li>
 *   <li>For each window position (MSB to LSB):
 *     <ul>
 *       <li>Bucket sort: bucket[j] += points[i] for window digit j</li>
 *       <li>Bucket reduction: running_sum = sum(j * bucket[j]) using prefix sum</li>
 *     </ul>
 *   </li>
 *   <li>Combine window results: shift each partial result by c bits via doubling</li>
 * </ol>
 *
 * <h3>Complexity</h3>
 * <p>Naive: O(n * 256) EC operations. Pippenger: O(n / c + 2^c) per window,
 * with 256/c windows. Optimal c ~ log2(n), giving O(n * 256 / log(n)).</p>
 *
 * <table>
 *   <tr><th>n</th><th>Naive</th><th>Pippenger</th><th>Speedup</th></tr>
 *   <tr><td>100</td><td>25,600</td><td>~5,000</td><td>5x</td></tr>
 *   <tr><td>1,000</td><td>256,000</td><td>~33,000</td><td>8x</td></tr>
 *   <tr><td>10,000</td><td>2,560,000</td><td>~250,000</td><td>10x</td></tr>
 * </table>
 */
public final class Pippenger {

    private Pippenger() {}

    private static final int SCALAR_BITS = 254; // BN254 Fr bit length

    /**
     * Compute the multi-scalar multiplication: sum(scalars[i] * points[i]).
     *
     * @param points  EC points (affine coordinates for efficiency)
     * @param scalars scalar multipliers as BigInteger
     * @return the MSM result as a Jacobian point
     */
    public static JacobianG1BN254 msm(JacobianG1BN254.AffineG1[] points, BigInteger[] scalars) {
        if (points.length != scalars.length)
            throw new IllegalArgumentException("points and scalars must have the same length");
        int n = points.length;
        if (n == 0) return JacobianG1BN254.INFINITY;
        if (n == 1) return JacobianG1BN254.fromAffine(points[0].x(), points[0].y()).scalarMul(scalars[0]);

        // Choose window size
        int c = windowSize(n);
        int numBuckets = (1 << c) - 1; // bucket indices 1..2^c - 1 (skip bucket 0)
        int numWindows = (SCALAR_BITS + c - 1) / c;

        // Process windows from MSB to LSB
        JacobianG1BN254 result = JacobianG1BN254.INFINITY;

        for (int w = numWindows - 1; w >= 0; w--) {
            // Shift result by c bits (double c times)
            if (!result.isInfinity()) {
                for (int d = 0; d < c; d++) {
                    result = result.doublePoint();
                }
            }

            // Initialize buckets
            JacobianG1BN254[] buckets = new JacobianG1BN254[numBuckets + 1];
            for (int i = 0; i <= numBuckets; i++) {
                buckets[i] = JacobianG1BN254.INFINITY;
            }

            // Bucket sort: for each scalar, extract window digit and add point to bucket
            int bitOffset = w * c;
            for (int i = 0; i < n; i++) {
                int digit = extractWindow(scalars[i], bitOffset, c);
                if (digit != 0) {
                    if (points[i].isInfinity()) continue;
                    buckets[digit] = buckets[digit].addAffine(points[i].x(), points[i].y());
                }
            }

            // Bucket reduction using running sum:
            // partial = sum_{j=1}^{2^c-1} j * bucket[j]
            // Computed as: running = bucket[2^c-1], partial += running,
            //              running += bucket[2^c-2], partial += running, ...
            JacobianG1BN254 runningSum = JacobianG1BN254.INFINITY;
            JacobianG1BN254 windowSum = JacobianG1BN254.INFINITY;

            for (int j = numBuckets; j >= 1; j--) {
                runningSum = runningSum.add(buckets[j]);
                windowSum = windowSum.add(runningSum);
            }

            result = result.add(windowSum);
        }

        return result;
    }

    /**
     * Naive MSM: sum(scalars[i] * points[i]) via individual scalar multiplications.
     * Used as a reference for testing.
     */
    public static JacobianG1BN254 naiveMsm(JacobianG1BN254.AffineG1[] points, BigInteger[] scalars) {
        JacobianG1BN254 result = JacobianG1BN254.INFINITY;
        for (int i = 0; i < points.length; i++) {
            if (scalars[i].signum() != 0 && !points[i].isInfinity()) {
                result = result.add(
                        JacobianG1BN254.fromAffine(points[i].x(), points[i].y()).scalarMul(scalars[i]));
            }
        }
        return result;
    }

    /**
     * Choose window size based on number of points.
     * Heuristic: c = max(3, floor(log2(n)))
     */
    static int windowSize(int n) {
        if (n <= 4) return 3;
        int logN = 31 - Integer.numberOfLeadingZeros(n); // floor(log2(n))
        return Math.max(3, Math.min(logN, 16));
    }

    /**
     * Extract a c-bit window from a scalar starting at bitOffset.
     */
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
