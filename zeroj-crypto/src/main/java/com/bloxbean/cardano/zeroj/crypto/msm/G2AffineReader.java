package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381;

import java.lang.foreign.MemorySegment;
import java.math.BigInteger;

/**
 * Reads affine G2 points from some backing store (ADR-0033 M3) — the G2 mirror of
 * {@link PippengerFlatBLS381.G1AffineReader}. ADR-0029 moved the four G1 proving-key arrays
 * off-heap (mmap) but left {@code pointsB2} on-heap as 43.7M nested {@code AffineG2} objects
 * (~15.7 GB at 19M constraints); this seam lets the G2 key stay in the mmap'd file too.
 *
 * <p>Two access forms, because the two MSM backends want different shapes: {@link #get} decodes a
 * point to an {@code AffineG2} (the pure-Java MSM), and {@link #readBE} copies the raw four
 * 48-byte big-endian coords {@code x.re‖x.im‖y.re‖y.im} — the {@code Groth16PkStore}
 * {@code pointsB2.bin} layout — so the blst backend can re-order bytes into its uncompressed
 * encoding without any field-element decoding. Infinity is all-zero coords in both forms.</p>
 */
public interface G2AffineReader {

    /** Number of points in the store. */
    int count();

    /** Decode point {@code i} to an affine G2 point (all-zero coords = infinity). */
    AffineG2 get(int i);

    /** Copy point {@code i}'s raw coords ({@code x.re‖x.im‖y.re‖y.im}, 48-byte BE each) into {@code dst[off..off+192)}. */
    void readBE(int i, byte[] dst, int off);

    /** {@link G2AffineReader} over an on-heap {@code AffineG2[]} (in-RAM PKs, tests). */
    final class HeapG2Reader implements G2AffineReader {
        private final AffineG2[] pts;

        public HeapG2Reader(AffineG2[] pts) { this.pts = pts; }

        @Override public int count() { return pts.length; }

        @Override public AffineG2 get(int i) { return pts[i]; }

        @Override public void readBE(int i, byte[] dst, int off) {
            AffineG2 p = pts[i];
            java.util.Arrays.fill(dst, off, off + 192, (byte) 0); // infinity = all zeros
            if (p.isInfinity()) return;
            to48BE(p.x().re().toBigInteger(), dst, off);
            to48BE(p.x().im().toBigInteger(), dst, off + 48);
            to48BE(p.y().re().toBigInteger(), dst, off + 96);
            to48BE(p.y().im().toBigInteger(), dst, off + 144);
        }

        private static void to48BE(BigInteger v, byte[] out, int off) {
            byte[] be = v.toByteArray();
            int s = Math.max(0, be.length - 48), len = be.length - s;
            System.arraycopy(be, s, out, off + 48 - len, len);
        }
    }

    /**
     * {@link G2AffineReader} over an mmap'd {@link MemorySegment} of {@code pointsB2.bin}
     * (192 bytes per point: four 48-byte big-endian coords) — file-backed, off-heap.
     */
    final class SegmentG2Reader implements G2AffineReader {
        private final MemorySegment seg;
        private final int count;

        public SegmentG2Reader(MemorySegment seg) {
            this.seg = seg;
            this.count = (int) (seg.byteSize() / 192L);
        }

        @Override public int count() { return count; }

        @Override public AffineG2 get(int i) {
            byte[] b = new byte[192];
            readBE(i, b, 0);
            return new AffineG2(
                    MontFp2_381.of(new BigInteger(1, b, 0, 48), new BigInteger(1, b, 48, 48)),
                    MontFp2_381.of(new BigInteger(1, b, 96, 48), new BigInteger(1, b, 144, 48)));
        }

        @Override public void readBE(int i, byte[] dst, int off) {
            MemorySegment.copy(seg, i * 192L, MemorySegment.ofArray(dst), off, 192);
        }
    }
}
