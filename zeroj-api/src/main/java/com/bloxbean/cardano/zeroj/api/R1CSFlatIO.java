package com.bloxbean.cardano.zeroj.api;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;

/**
 * Persists an {@link R1CSFlat} to disk and loads it back (ADR-0034 M4) — the compile-once cache.
 *
 * <p>Compiling the 19M-constraint circuit takes ~17 s and several GB of transient heap on
 * <em>every</em> prove, yet the output is a pure function of the circuit. This caches the packed
 * CSR matrices next to the key bundle, keyed by the circuit <b>fingerprint</b>; a prove whose
 * bundle fingerprint matches the cache skips {@code compileR1CS} entirely (the circuit graph is
 * still built — witness calculation needs it).</p>
 *
 * <p>Integrity: the fingerprint gate means a stale/foreign cache is simply ignored. A tampered
 * cache cannot produce a false proof — Groth16 soundness ties a valid proof to the key bundle's
 * own QAP, so wrong constraints yield a proof that fails the pairing self-check/verify.</p>
 *
 * <p>Format (little-endian): {@code "ZJRF" | u32 version=1 | u16 fpLen | fp (UTF-8) | u32 rows |
 * u32 dictSize | 3 × (u32 nnz | int[rows+1] rowOffsets | int[nnz] wireIdx | int[nnz] coeffIdx) |
 * dictSize × 32-byte BE canonical Fr}.</p>
 */
public final class R1CSFlatIO {

    private R1CSFlatIO() {}

    private static final int MAGIC = 0x5A4A5246; // "ZJRF"
    private static final int VERSION = 1;

    /** Write {@code flat} to {@code file} (atomically via a temp sibling). */
    public static void write(R1CSFlat flat, String fingerprint, Path file) throws IOException {
        byte[] fp = fingerprint.getBytes(StandardCharsets.UTF_8);
        if (fp.length > 0xffff) throw new IllegalArgumentException("fingerprint too long");
        BigInteger[] dict = flat.dictionary();

        long size = 4 + 4 + 2 + fp.length + 4 + 4
                + matrixBytes(flat.a(), flat.rows()) + matrixBytes(flat.b(), flat.rows())
                + matrixBytes(flat.c(), flat.rows())
                + (long) dict.length * 32;
        if (size > Integer.MAX_VALUE)
            throw new IOException("R1CS cache would exceed 2 GB (" + size + " bytes) — not supported");

        Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.READ,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
             Arena arena = Arena.ofConfined()) {
            ByteBuffer buf = ch.map(FileChannel.MapMode.READ_WRITE, 0, size, arena)
                    .asByteBuffer().order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt(MAGIC).putInt(VERSION);
            buf.putShort((short) fp.length).put(fp);
            buf.putInt(flat.rows()).putInt(dict.length);
            putMatrix(buf, flat.a());
            putMatrix(buf, flat.b());
            putMatrix(buf, flat.c());
            byte[] be32 = new byte[32];
            for (BigInteger v : dict) {
                java.util.Arrays.fill(be32, (byte) 0);
                byte[] be = v.toByteArray();
                int s = Math.max(0, be.length - 32), len = be.length - s;
                System.arraycopy(be, s, be32, 32 - len, len);
                buf.put(be32);
            }
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Header-only probe: does {@code file} look like a cache for {@code expectedFingerprint}?
     * Cheap (reads a few hundred bytes) — lets a caller decide to skip compiling early but defer
     * the full ~1 GB load until the moment the constraints are actually needed (so they never
     * coexist with the witness-generation peak).
     */
    public static boolean hasMatching(Path file, String expectedFingerprint) {
        if (!Files.isRegularFile(file)) return false;
        byte[] expected = expectedFingerprint.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buf = ByteBuffer.allocate(4 + 4 + 2 + expected.length).order(ByteOrder.LITTLE_ENDIAN);
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            while (buf.hasRemaining() && ch.read(buf) >= 0) { /* fill */ }
            if (buf.hasRemaining()) return false;
            buf.flip();
            if (buf.getInt() != MAGIC || buf.getInt() != VERSION) return false;
            if ((buf.getShort() & 0xffff) != expected.length) return false;
            byte[] fp = new byte[expected.length];
            buf.get(fp);
            return java.util.Arrays.equals(fp, expected);
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    /**
     * Read a cache written by {@link #write}; returns {@code null} when the file is missing,
     * malformed, a different version, or carries a different fingerprint — callers treat all of
     * those as a cache miss and recompile.
     */
    public static R1CSFlat readIfMatches(Path file, String expectedFingerprint) {
        if (!Files.isRegularFile(file)) return null;
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ);
             Arena arena = Arena.ofConfined()) {
            ByteBuffer buf = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size(), arena)
                    .asByteBuffer().order(ByteOrder.LITTLE_ENDIAN);
            if (buf.remaining() < 16 || buf.getInt() != MAGIC || buf.getInt() != VERSION) return null;
            byte[] fp = new byte[buf.getShort() & 0xffff];
            buf.get(fp);
            if (!new String(fp, StandardCharsets.UTF_8).equals(expectedFingerprint)) return null;
            int rows = buf.getInt();
            int dictSize = buf.getInt();
            if (rows < 0 || dictSize < 0) return null;

            R1CSFlat.Matrix a = getMatrix(buf, rows);
            R1CSFlat.Matrix b = getMatrix(buf, rows);
            R1CSFlat.Matrix c = getMatrix(buf, rows);

            BigInteger[] dict = new BigInteger[dictSize];
            byte[] be32 = new byte[32];
            for (int i = 0; i < dictSize; i++) {
                buf.get(be32);
                dict[i] = new BigInteger(1, be32);
            }
            return R1CSFlat.fromArrays(rows, a, b, c, dict);
        } catch (IOException | RuntimeException e) {
            return null; // treat any corruption as a miss
        }
    }

    /**
     * Map a cache written by {@link #write} into {@code arena} and read the matrices <b>off-heap</b>
     * (ADR-0034 M6a): the CSR arrays stay file-backed {@link R1CSFlat.SegmentMatrix} slices — only
     * the small coefficient dictionary is materialized. The returned flat is valid for the arena's
     * lifetime. Returns {@code null} on missing/malformed/foreign-fingerprint files (cache miss).
     */
    public static R1CSFlat readMapped(Path file, String expectedFingerprint, Arena arena) {
        if (!Files.isRegularFile(file)) return null;
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            var seg = ch.map(FileChannel.MapMode.READ_ONLY, 0, ch.size(), arena);
            ByteBuffer header = seg.asSlice(0, Math.min(seg.byteSize(), 1 << 16))
                    .asByteBuffer().order(ByteOrder.LITTLE_ENDIAN);
            if (header.remaining() < 16 || header.getInt() != MAGIC || header.getInt() != VERSION) return null;
            byte[] fp = new byte[header.getShort() & 0xffff];
            header.get(fp);
            if (!new String(fp, StandardCharsets.UTF_8).equals(expectedFingerprint)) return null;
            int rows = header.getInt();
            int dictSize = header.getInt();
            if (rows < 0 || dictSize < 0) return null;

            long pos = header.position();
            R1CSFlat.Matrix[] ms = new R1CSFlat.Matrix[3];
            for (int m = 0; m < 3; m++) {
                int nnz = seg.get(java.lang.foreign.ValueLayout.JAVA_INT_UNALIGNED
                        .withOrder(ByteOrder.LITTLE_ENDIAN), pos);
                pos += 4;
                long offBytes = (long) (rows + 1) * 4, idxBytes = (long) nnz * 4;
                ms[m] = new R1CSFlat.SegmentMatrix(
                        seg.asSlice(pos, offBytes),
                        seg.asSlice(pos + offBytes, idxBytes),
                        seg.asSlice(pos + offBytes + idxBytes, idxBytes), nnz);
                pos += offBytes + 2 * idxBytes;
            }

            BigInteger[] dict = new BigInteger[dictSize];
            byte[] be32 = new byte[32];
            for (int i = 0; i < dictSize; i++) {
                java.lang.foreign.MemorySegment.copy(seg, pos + (long) i * 32,
                        java.lang.foreign.MemorySegment.ofArray(be32), 0, 32);
                dict[i] = new BigInteger(1, be32);
            }
            return R1CSFlat.fromArrays(rows, ms[0], ms[1], ms[2], dict);
        } catch (IOException | RuntimeException e) {
            return null; // treat any corruption as a miss
        }
    }

    private static long matrixBytes(R1CSFlat.Matrix m, int rows) {
        return 4 + (long) (rows + 1) * 4 + (long) m.nnz() * 8;
    }

    private static void putMatrix(ByteBuffer buf, R1CSFlat.Matrix m) {
        if (!(m instanceof R1CSFlat.HeapMatrix h))
            throw new IllegalArgumentException("only heap-backed R1CSFlat can be written (got " + m.getClass() + ")");
        buf.putInt(h.nnz());
        putInts(buf, h.rowOffsets());
        putInts(buf, h.wireIdx());
        putInts(buf, h.coeffIdx());
    }

    private static R1CSFlat.Matrix getMatrix(ByteBuffer buf, int rows) {
        int nnz = buf.getInt();
        return new R1CSFlat.HeapMatrix(getInts(buf, rows + 1), getInts(buf, nnz), getInts(buf, nnz));
    }

    private static void putInts(ByteBuffer buf, int[] a) {
        buf.asIntBuffer().put(a);                 // bulk copy
        buf.position(buf.position() + a.length * 4);
    }

    private static int[] getInts(ByteBuffer buf, int n) {
        int[] a = new int[n];
        buf.asIntBuffer().get(a);
        buf.position(buf.position() + n * 4);
        return a;
    }
}
