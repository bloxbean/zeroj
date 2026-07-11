package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;
import com.bloxbean.cardano.zeroj.crypto.msm.G2AffineReader;
import com.bloxbean.cardano.zeroj.crypto.msm.PippengerFlatBLS381;

import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteOrder;

/**
 * Sparse point-file format (ADR-0035 M6a): a presence bitmap + per-block rank prefix sums +
 * densely packed non-infinity points.
 *
 * <p>Measured on the 19M account-ownership bundle, <b>57.8 % of all key points are the point at
 * infinity</b> (wires absent from a matrix's rows; 80.6 % in B1/B2) — 15 GB of literal zero
 * bytes in the dense layout. This format stores each point once and answers infinity from a
 * 1 bit/point bitmap: 24.2 GB → ~9.3 GB on disk, and the prove's key working set shrinks the
 * same 2.6×. Readers implement the ADR-0033 reader seams, so the prover is untouched.</p>
 *
 * <p>Layout (bitmap/rank little-endian; point payloads keep the dense formats — native-order
 * G1 limbs, big-endian G2 coords):</p>
 * <pre>
 * u32 magic "ZJSP" | u32 version=1 | u32 stride (96 G1 / 192 G2) | u32 blockSize=512
 * u64 count | u64 nnz
 * bitmap  : ceil(count/64) × u64
 * rank    : ceil(count/512) × u32   (non-infinity points BEFORE each block)
 * padding : to an 8-byte boundary
 * points  : nnz × stride
 * </pre>
 */
public final class SparsePointFile {

    private SparsePointFile() {}

    public static final int MAGIC = 0x5A4A5350; // "ZJSP"
    public static final int VERSION = 1;
    public static final int BLOCK = 512;

    private static final ValueLayout.OfInt LE_INT = ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final ValueLayout.OfLong LE_LONG = ValueLayout.JAVA_LONG_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);

    /** Total file size for {@code count} points of which {@code nnz} are present. */
    public static long fileSize(long count, long nnz, int stride) {
        return pointsOffset(count) + nnz * stride;
    }

    /** Byte offset of the packed points region. */
    public static long pointsOffset(long count) {
        long words = (count + 63) >>> 6;
        long blocks = (count + BLOCK - 1) / BLOCK;
        long o = 32 + words * 8 + blocks * 4;
        return (o + 7) & ~7L; // 8-byte alignment for native-order limb reads
    }

    /** Write the header + bitmap + rank sections into a freshly mapped segment. */
    public static void writeIndex(MemorySegment seg, long[] bitmap, long count, long nnz, int stride) {
        seg.set(LE_INT, 0, MAGIC);
        seg.set(LE_INT, 4, VERSION);
        seg.set(LE_INT, 8, stride);
        seg.set(LE_INT, 12, BLOCK);
        seg.set(LE_LONG, 16, count);
        seg.set(LE_LONG, 24, nnz);
        long words = (count + 63) >>> 6;
        for (long w = 0; w < words; w++) seg.set(LE_LONG, 32 + w * 8, bitmap[(int) w]);
        long rankOff = 32 + words * 8;
        long blocks = (count + BLOCK - 1) / BLOCK;
        int running = 0;
        for (long b = 0; b < blocks; b++) {
            seg.set(LE_INT, rankOff + b * 4, running);
            int from = (int) (b * BLOCK / 64);
            int to = (int) Math.min(words, (b + 1) * BLOCK / 64);
            for (int w = from; w < to; w++) running += Long.bitCount(bitmap[w]);
        }
        if (running != nnz) throw new IllegalStateException("bitmap nnz " + running + " != " + nnz);
    }

    /** Shared index over a mapped sparse file: bitmap membership + rank lookup. */
    public static final class Index {
        final MemorySegment seg;
        final long count;
        final long nnz;
        final int stride;
        final long rankOff;
        final long ptsOff;

        public Index(MemorySegment seg) {
            this.seg = seg;
            if (seg.get(LE_INT, 0) != MAGIC || seg.get(LE_INT, 4) != VERSION)
                throw new IllegalArgumentException("not a ZJSP v1 sparse point file");
            this.stride = seg.get(LE_INT, 8);
            if (seg.get(LE_INT, 12) != BLOCK)
                throw new IllegalArgumentException("unsupported block size");
            this.count = seg.get(LE_LONG, 16);
            this.nnz = seg.get(LE_LONG, 24);
            long words = (count + 63) >>> 6;
            this.rankOff = 32 + words * 8;
            this.ptsOff = pointsOffset(count);
        }

        public int count() { return (int) count; }

        boolean present(int i) {
            long word = seg.get(LE_LONG, 32 + ((long) (i >>> 6)) * 8);
            return (word >>> (i & 63) & 1L) != 0;
        }

        /** Packed position of point {@code i} (callers must have checked {@link #present}). */
        long rank(int i) {
            int block = i >>> 9;
            long r = seg.get(LE_INT, rankOff + (long) block * 4) & 0xffffffffL;
            int wordFrom = block << 3;               // 512/64 = 8 words per block
            int wordTo = i >>> 6;
            for (int w = wordFrom; w < wordTo; w++)
                r += Long.bitCount(seg.get(LE_LONG, 32 + (long) w * 8));
            long partial = seg.get(LE_LONG, 32 + (long) wordTo * 8) & ((1L << (i & 63)) - 1);
            return r + Long.bitCount(partial);
        }

        long pointOffset(int i) { return ptsOff + rank(i) * (long) stride; }
    }

    /** Sparse G1 reader (12 native-order limbs per present point); infinity → zero limbs. */
    public static final class SparseG1Reader implements PippengerFlatBLS381.G1AffineReader {
        private final Index idx;

        public SparseG1Reader(MemorySegment seg) { this.idx = new Index(seg); }

        @Override public int count() { return idx.count(); }

        @Override public void readInto(int i, long[] buf) {
            if (!idx.present(i)) {
                java.util.Arrays.fill(buf, 0, 12, 0L);
                return;
            }
            long o = idx.pointOffset(i);
            for (int k = 0; k < 12; k++) buf[k] = idx.seg.get(ValueLayout.JAVA_LONG_UNALIGNED, o + k * 8L);
        }
    }

    /** Sparse G2 reader (192 BE bytes per present point); infinity → zeros / {@code INFINITY}. */
    public static final class SparseG2Reader implements G2AffineReader {
        private final Index idx;

        public SparseG2Reader(MemorySegment seg) { this.idx = new Index(seg); }

        @Override public int count() { return idx.count(); }

        @Override public AffineG2 get(int i) {
            if (!idx.present(i)) return AffineG2.INFINITY;
            byte[] b = new byte[192];
            readAt(i, b, 0);
            return new AffineG2(
                    MontFp2_381.of(new BigInteger(1, b, 0, 48), new BigInteger(1, b, 48, 48)),
                    MontFp2_381.of(new BigInteger(1, b, 96, 48), new BigInteger(1, b, 144, 48)));
        }

        @Override public void readBE(int i, byte[] dst, int off) {
            if (!idx.present(i)) {
                java.util.Arrays.fill(dst, off, off + 192, (byte) 0);
                return;
            }
            readAt(i, dst, off);
        }

        private void readAt(int i, byte[] dst, int off) {
            MemorySegment.copy(idx.seg, idx.pointOffset(i), MemorySegment.ofArray(dst), off, 192);
        }
    }
}
