package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;

/**
 * Groth16 proving key for BLS12-381.
 *
 * @see Groth16ProvingKey
 */
public record Groth16ProvingKeyBLS381(
        AffineG1 alphaG1,
        AffineG1 betaG1,
        AffineG2 betaG2,
        AffineG1 deltaG1,
        AffineG2 deltaG2,
        // ADR-0029 M2b: G1 point arrays are stored FLAT — 12 Montgomery longs per affine point
        // (x[6],y[6]); affine infinity is (0,0). No per-point object overhead (~1.75× smaller than
        // AffineG1[]) and mmap-able (M4). Point i is at {@code pointsX[i*12 .. i*12+11]}.
        long[] pointsA,
        long[] pointsB1,
        AffineG2[] pointsB2,
        long[] pointsH,
        long[] pointsL,
        int numPublic
) {
    /** Longs per flat G1 affine point (x[6], y[6]). */
    public static final int G1_STRIDE = 12;

    /** Number of G1 points in a flat array. */
    public static int count(long[] flatG1) { return flatG1.length / G1_STRIDE; }

    /** Write affine point {@code p} at index {@code i} of a flat G1 array (infinity ⇒ zeros). */
    public static void writeG1(long[] flat, int i, AffineG1 p) {
        int off = i * G1_STRIDE;
        if (p.isInfinity()) {
            java.util.Arrays.fill(flat, off, off + G1_STRIDE, 0L);
        } else {
            System.arraycopy(p.x().toLimbs(), 0, flat, off, 6);
            System.arraycopy(p.y().toLimbs(), 0, flat, off + 6, 6);
        }
    }

    /** Reconstruct affine point {@code i} from a flat G1 array. */
    public static AffineG1 readG1(long[] flat, int i) {
        int off = i * G1_STRIDE;
        boolean inf = true;
        for (int k = 0; k < G1_STRIDE; k++) if (flat[off + k] != 0L) { inf = false; break; }
        if (inf) return AffineG1.INFINITY;
        var x = com.bloxbean.cardano.zeroj.bls12381.field.MontFp381.fromMontLimbs(
                flat[off], flat[off+1], flat[off+2], flat[off+3], flat[off+4], flat[off+5]);
        var y = com.bloxbean.cardano.zeroj.bls12381.field.MontFp381.fromMontLimbs(
                flat[off+6], flat[off+7], flat[off+8], flat[off+9], flat[off+10], flat[off+11]);
        return new AffineG1(x, y);
    }

    /** Pack an {@code AffineG1[]} into a flat G1 array (for serialization / import boundaries). */
    public static long[] flattenG1(AffineG1[] pts) {
        long[] flat = new long[pts.length * G1_STRIDE];
        for (int i = 0; i < pts.length; i++) writeG1(flat, i, pts[i]);
        return flat;
    }

    /** Reconstruct an {@code AffineG1[]} from a flat G1 array (serialization / test boundaries). */
    public static AffineG1[] toAffineArray(long[] flat) {
        int n = count(flat);
        AffineG1[] pts = new AffineG1[n];
        for (int i = 0; i < n; i++) pts[i] = readG1(flat, i);
        return pts;
    }
}
