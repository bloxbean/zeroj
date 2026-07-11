package com.bloxbean.cardano.zeroj.crypto.msm;

import java.math.BigInteger;

/**
 * Flat, canonical (non-Montgomery) BLS12-381 Fr scalars: value {@code i} is four little-endian
 * 64-bit limbs at {@code (offset+i)*4} (ADR-0034 M3).
 *
 * <p>The witness and H-coefficient vectors were {@code BigInteger[]} — ~60 B per scalar of object
 * + magnitude overhead (5+ GB at 43.7M wires), re-encoded per MSM (32-byte LE arrays in the
 * pure-Java Pippenger, per-scalar byte marshalling in blst). This packs them once at 32 B/scalar;
 * MSM window extraction and blst's little-endian encoding read the limbs directly, and
 * {@code computeH} converts limbs to Montgomery form in place with {@code FrArith381} — no boxing
 * anywhere on the prove path.</p>
 *
 * <p><b>Invariant:</b> every value is fully reduced ({@code 0 <= v < r}) — {@link #pack} reduces;
 * producers of raw limb arrays (e.g. {@code computeH}) must emit canonical values. Consumers
 * (window extraction, blst encoding) rely on it.</p>
 *
 * <p>{@link #slice} returns an O(1) view — {@code ParallelMsm} chunks scalars without copying.</p>
 */
public final class FlatScalars {

    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private final long[] limbs;
    private final int offset; // in scalars
    private final int count;

    private FlatScalars(long[] limbs, int offset, int count) {
        this.limbs = limbs;
        this.offset = offset;
        this.count = count;
    }

    /** Pack the first {@code n} values, reducing any out-of-range value mod r. */
    public static FlatScalars pack(BigInteger[] values, int n) {
        long[] limbs = new long[n * 4];
        for (int i = 0; i < n; i++) {
            BigInteger v = values[i];
            if (v.signum() < 0 || v.compareTo(FR) >= 0) v = v.mod(FR);
            limbsOf(v, limbs, i * 4);
        }
        return new FlatScalars(limbs, 0, n);
    }

    /**
     * {@link #pack}, but <b>consumes</b> the input: {@code values[i]} is nulled as it is packed,
     * so the boxed elements (~60 B each — GBs at 43.7M scalars) become collectable progressively
     * instead of coexisting with the packed form until the caller drops the array.
     */
    public static FlatScalars packConsuming(BigInteger[] values, int n) {
        long[] limbs = new long[n * 4];
        for (int i = 0; i < n; i++) {
            BigInteger v = values[i];
            values[i] = null;
            if (v.signum() < 0 || v.compareTo(FR) >= 0) v = v.mod(FR);
            limbsOf(v, limbs, i * 4);
        }
        return new FlatScalars(limbs, 0, n);
    }

    /** Wrap already-canonical limbs (value {@code i} at {@code i*4}; caller must not mutate). */
    public static FlatScalars wrap(long[] canonicalLimbs, int count) {
        return new FlatScalars(canonicalLimbs, 0, count);
    }

    public int count() { return count; }

    /** O(1) view of {@code len} scalars starting at {@code from}. */
    public FlatScalars slice(int from, int len) {
        if (from < 0 || len < 0 || from + len > count)
            throw new IndexOutOfBoundsException(from + "+" + len + " of " + count);
        return new FlatScalars(limbs, offset + from, len);
    }

    /** Copy scalar {@code i}'s four limbs into {@code dst[dstOff..dstOff+4)}. */
    public void copyLimbs(int i, long[] dst, int dstOff) {
        System.arraycopy(limbs, (offset + i) * 4, dst, dstOff, 4);
    }

    /** True if scalar {@code i} is zero. */
    public boolean isZero(int i) {
        int b = (offset + i) * 4;
        return (limbs[b] | limbs[b + 1] | limbs[b + 2] | limbs[b + 3]) == 0;
    }

    /**
     * The window digit {@code bits} wide at {@code bitOffset} of scalar {@code i} — the flat-limb
     * equivalent of per-bit {@code BigInteger.testBit} / LE-byte extraction ({@code bits <= 16}).
     */
    public int window(int i, int bitOffset, int bits) {
        int base = (offset + i) * 4;
        int limb = bitOffset >>> 6, shift = bitOffset & 63;
        if (limb >= 4) return 0;
        long acc = limbs[base + limb] >>> shift;
        // spill into the next limb (shift==0 never spills for bits<=64)
        if (shift + bits > 64 && limb + 1 < 4) acc |= limbs[base + limb + 1] << (64 - shift);
        return (int) (acc & ((1L << bits) - 1));
    }

    /** Scalar {@code i} as 32 little-endian bytes into {@code dst} (the blst scalar convention). */
    public void leBytes(int i, byte[] dst) {
        int base = (offset + i) * 4;
        for (int j = 0; j < 4; j++) {
            long l = limbs[base + j];
            int o = j * 8;
            dst[o] = (byte) l;
            dst[o + 1] = (byte) (l >>> 8);
            dst[o + 2] = (byte) (l >>> 16);
            dst[o + 3] = (byte) (l >>> 24);
            dst[o + 4] = (byte) (l >>> 32);
            dst[o + 5] = (byte) (l >>> 40);
            dst[o + 6] = (byte) (l >>> 48);
            dst[o + 7] = (byte) (l >>> 56);
        }
    }

    /** Scalar {@code i} as a BigInteger (compat/diagnostics; allocates). */
    public BigInteger toBigInteger(int i) {
        byte[] be = new byte[32];
        int base = (offset + i) * 4;
        for (int j = 0; j < 4; j++) {
            long l = limbs[base + j];
            int o = 24 - j * 8;
            for (int k = 0; k < 8; k++) be[o + 7 - k] = (byte) (l >>> (8 * k));
        }
        return new BigInteger(1, be);
    }

    /** Canonical limbs of {@code v} ({@code 0 <= v < 2^256}) into {@code dst[off..off+4)}. */
    private static void limbsOf(BigInteger v, long[] dst, int off) {
        byte[] be = v.toByteArray(); // may carry one leading 0x00 sign byte
        int len = Math.min(be.length, 32);
        for (int k = 0; k < len; k++) {
            int b = be[be.length - 1 - k] & 0xff;
            dst[off + (k >>> 3)] |= (long) b << ((k & 7) << 3);
        }
    }
}
