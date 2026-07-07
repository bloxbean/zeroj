package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianArith381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;

import java.math.BigInteger;

/**
 * Fixed-base scalar multiplication on the BLS12-381 G1 generator, for Groth16 setup (ADR-0029 M2a).
 *
 * <p>Groth16 setup computes {@code s·G} for millions of scalars against the <b>same</b> generator.
 * A one-time precomputed comb table (window {@value #W} bits, {@value #NUM_WINDOWS} windows) turns
 * each scalar-mul into ≤{@value #NUM_WINDOWS} mixed additions with <b>no doublings</b>, over the
 * allocation-free flat arithmetic ({@link JacobianArith381}) — replacing the ~255 doubling +
 * ~128 add object-allocating double-and-add of {@link JacobianG1BLS381#scalarMul}.</p>
 *
 * <p>Table entry {@code (w,d)} = {@code d · 2^(W·w) · G} in affine form. Differential-tested against
 * {@link JacobianG1BLS381#scalarMul} (see {@code FixedBaseG1BLS381Test}).</p>
 */
public final class FixedBaseG1BLS381 {

    private FixedBaseG1BLS381() {}

    static final int W = 4;                     // window bits
    static final int DIGITS = 1 << W;           // 16 (digit 0 skipped)
    static final int NUM_WINDOWS = (255 + W - 1) / W; // 64
    private static final int AFF = 12;          // affine longs per entry (x[6],y[6])

    // TABLE[(w*(DIGITS-1) + (d-1)) * AFF ...] = affine limbs of d·2^(W·w)·G, for d in 1..15.
    private static volatile long[] TABLE;

    private static long[] table() {
        long[] t = TABLE;
        if (t == null) {
            synchronized (FixedBaseG1BLS381.class) {
                t = TABLE;
                if (t == null) TABLE = t = buildTable();
            }
        }
        return t;
    }

    /** {@code s·G} as a {@link JacobianG1BLS381} (affine internally). */
    public static JacobianG1BLS381 mul(BigInteger s) {
        long[] tab = table();
        if (s.signum() == 0) return JacobianG1BLS381.INFINITY;
        byte[] le = leBytes32(s.mod(ORDER));
        long[] scratch = new long[JacobianArith381.SCRATCH_LONGS];
        long[] out = new long[JacobianArith381.POINT_LONGS];
        JacobianArith381.setInfinity(out, 0);
        for (int w = 0; w < NUM_WINDOWS; w++) {
            int digit = extractWindow(le, w * W);
            if (digit == 0) continue;
            int eo = (w * (DIGITS - 1) + (digit - 1)) * AFF;
            JacobianArith381.addAffine(out, 0, out, 0, tab, eo, tab, eo + 6, scratch);
        }
        return toJacobian(out);
    }

    /** {@code s·G} directly as an affine G1 (setup's shape). */
    public static JacobianG1BLS381.AffineG1 mulAffine(BigInteger s) {
        return mul(s).toAffine();
    }

    // ------------------------------------------------------------------

    private static final BigInteger ORDER = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private static long[] buildTable() {
        long[] tab = new long[NUM_WINDOWS * (DIGITS - 1) * AFF];
        long[] s = new long[JacobianArith381.SCRATCH_LONGS];

        // baseW (flat Jacobian) starts at G, ×2^W each window.
        var gAff = JacobianG1BLS381.GENERATOR.toAffine();
        long[] baseW = new long[JacobianArith381.POINT_LONGS];
        JacobianArith381.fromAffine(baseW, 0, gAff.x().toLimbs(), 0, gAff.y().toLimbs(), 0);

        long[] acc = new long[JacobianArith381.POINT_LONGS];
        long[] tmp = new long[JacobianArith381.POINT_LONGS];
        for (int w = 0; w < NUM_WINDOWS; w++) {
            JacobianArith381.copyPoint(acc, 0, baseW, 0);          // acc = 1·baseW
            writeAffine(tab, (w * (DIGITS - 1)) * AFF, acc);
            for (int d = 2; d < DIGITS; d++) {
                JacobianArith381.add(acc, 0, acc, 0, baseW, 0, s); // acc += baseW → d·baseW
                writeAffine(tab, (w * (DIGITS - 1) + (d - 1)) * AFF, acc);
            }
            // baseW ← 2^W · baseW
            for (int k = 0; k < W; k++) { JacobianArith381.dbl(tmp, 0, baseW, 0, s); JacobianArith381.copyPoint(baseW, 0, tmp, 0); }
        }
        return tab;
    }

    /** Convert flat Jacobian (non-infinity) → affine limbs into {@code tab[off..off+11]}. */
    private static void writeAffine(long[] tab, int off, long[] jac) {
        MontFp381 x = MontFp381.fromMontLimbs(jac[0], jac[1], jac[2], jac[3], jac[4], jac[5]);
        MontFp381 y = MontFp381.fromMontLimbs(jac[6], jac[7], jac[8], jac[9], jac[10], jac[11]);
        MontFp381 z = MontFp381.fromMontLimbs(jac[12], jac[13], jac[14], jac[15], jac[16], jac[17]);
        MontFp381 zi = z.inverse(), zi2 = zi.square(), zi3 = zi2.mul(zi);
        System.arraycopy(x.mul(zi2).toLimbs(), 0, tab, off, 6);
        System.arraycopy(y.mul(zi3).toLimbs(), 0, tab, off + 6, 6);
    }

    private static JacobianG1BLS381 toJacobian(long[] p) {
        if (JacobianArith381.isInfinity(p, 0)) return JacobianG1BLS381.INFINITY;
        MontFp381 x = MontFp381.fromMontLimbs(p[0], p[1], p[2], p[3], p[4], p[5]);
        MontFp381 y = MontFp381.fromMontLimbs(p[6], p[7], p[8], p[9], p[10], p[11]);
        MontFp381 z = MontFp381.fromMontLimbs(p[12], p[13], p[14], p[15], p[16], p[17]);
        MontFp381 zi = z.inverse(), zi2 = zi.square(), zi3 = zi2.mul(zi);
        return JacobianG1BLS381.fromAffine(x.mul(zi2), y.mul(zi3));
    }

    private static int extractWindow(byte[] le, int bitOffset) {
        int digit = 0;
        for (int b = 0; b < W; b++) {
            int bitPos = bitOffset + b, byteIdx = bitPos >>> 3;
            if (byteIdx < le.length) digit |= ((le[byteIdx] >>> (bitPos & 7)) & 1) << b;
        }
        return digit;
    }

    private static byte[] leBytes32(BigInteger v) {
        byte[] be = v.toByteArray(), le = new byte[32];
        for (int i = 0; i < be.length && i < 32; i++) le[i] = be[be.length - 1 - i];
        return le;
    }
}
