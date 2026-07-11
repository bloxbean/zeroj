package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;

import java.math.BigInteger;

/**
 * Fixed-base scalar multiplication on the BLS12-381 G2 generator, for Groth16 setup
 * (ADR-0035 M4) — the G2 mirror of {@link FixedBaseG1BLS381}.
 *
 * <p>Setup computes {@code s·G2} for tens of millions of scalars against the <b>same</b>
 * generator; the generic {@code scalarMul} does ~255 object-allocating double-and-adds per
 * point and was the dominant setup cost. A one-time comb table (window {@value #W} bits,
 * {@value #NUM_WINDOWS} windows) turns each into ≤{@value #NUM_WINDOWS} additions with no
 * doublings. Results are returned in Jacobian form so callers can batch the affine
 * normalization ({@link JacobianG2BLS381#batchToAffine}) — one Fp2 inversion per block instead
 * of one per point. Differential-tested against {@code scalarMul} (see
 * {@code FixedBaseG2BLS381Test}).</p>
 */
public final class FixedBaseG2BLS381 {

    private FixedBaseG2BLS381() {}

    // W=8 (ADR-0035 M5): 32 windows × 255 Jacobian entries, built once in ~1 s — halves the
    // additions per scalar-mul vs W=4.
    static final int W = 8;                           // window bits
    static final int DIGITS = 1 << W;                 // 256 (digit 0 skipped)
    static final int NUM_WINDOWS = (255 + W - 1) / W; // 32

    // TABLE[w*(DIGITS-1) + (d-1)] = d · 2^(W·w) · G2 (Jacobian; immutable objects)
    private static volatile JacobianG2BLS381[] TABLE;

    private static JacobianG2BLS381[] table() {
        JacobianG2BLS381[] t = TABLE;
        if (t == null) {
            synchronized (FixedBaseG2BLS381.class) {
                t = TABLE;
                if (t == null) TABLE = t = buildTable();
            }
        }
        return t;
    }

    /**
     * {@code s·G2} in Jacobian form from four canonical little-endian limbs; {@code null} for a
     * zero scalar. The caller batch-normalizes.
     */
    public static JacobianG2BLS381 mulJacobian(long[] canonLe4, int off) {
        if ((canonLe4[off] | canonLe4[off + 1] | canonLe4[off + 2] | canonLe4[off + 3]) == 0) return null;
        JacobianG2BLS381[] tab = table();
        JacobianG2BLS381 acc = null;
        for (int w = 0; w < NUM_WINDOWS; w++) {
            int digit = windowOfLimbs(canonLe4, off, w * W);
            if (digit == 0) continue;
            JacobianG2BLS381 e = tab[w * (DIGITS - 1) + (digit - 1)];
            acc = acc == null ? e : acc.add(e);
        }
        return acc;
    }

    /** {@code s·G2} (boxed scalar; reduces mod r) — tests/diagnostics. */
    public static JacobianG2BLS381 mulJacobian(BigInteger s) {
        BigInteger v = s.mod(ORDER);
        long[] canon = new long[4];
        byte[] be = v.toByteArray();
        int len = Math.min(be.length, 32);
        for (int k = 0; k < len; k++)
            canon[k >>> 3] |= ((long) (be[be.length - 1 - k] & 0xff)) << ((k & 7) << 3);
        JacobianG2BLS381 r = mulJacobian(canon, 0);
        return r == null ? JacobianG2BLS381.INFINITY : r;
    }

    // ------------------------------------------------------------------

    private static final BigInteger ORDER = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private static JacobianG2BLS381[] buildTable() {
        JacobianG2BLS381[] tab = new JacobianG2BLS381[NUM_WINDOWS * (DIGITS - 1)];
        JacobianG2BLS381 baseW = JacobianG2BLS381.GENERATOR;
        for (int w = 0; w < NUM_WINDOWS; w++) {
            JacobianG2BLS381 acc = baseW;
            tab[w * (DIGITS - 1)] = acc;
            for (int d = 2; d < DIGITS; d++) {
                acc = acc.add(baseW);
                tab[w * (DIGITS - 1) + (d - 1)] = acc;
            }
            for (int k = 0; k < W; k++) baseW = baseW.doublePoint();
        }
        return tab;
    }

    private static int windowOfLimbs(long[] limbs, int off, int bitOffset) {
        int limb = bitOffset >>> 6, shift = bitOffset & 63;
        if (limb >= 4) return 0;
        long acc = limbs[off + limb] >>> shift;
        if (shift + W > 64 && limb + 1 < 4) acc |= limbs[off + limb + 1] << (64 - shift);
        return (int) (acc & ((1L << W) - 1));
    }
}
