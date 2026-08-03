package com.bloxbean.cardano.zeroj.api;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Persists an {@link R1CSFlat} to disk and loads it back (ADR-0034 M4) — the compile-once cache.
 *
 * <p>Compiling the 19M-constraint circuit takes ~17 s and several GB of transient heap on
 * <em>every</em> prove, yet the output is a pure function of the circuit. This caches the packed
 * CSR matrices next to the key bundle, keyed by the circuit <b>fingerprint</b>; a prove whose
 * bundle fingerprint matches the cache skips {@code compileR1CS} entirely (the circuit graph is
 * still built — witness calculation needs it).</p>
 *
 * <p>Integrity: exact fingerprints ({@code c...-w...-p...-r&lt;sha256&gt;}) are recomputed from
 * the decoded relation on both write and read. A stale, foreign, or tampered cache is therefore a
 * cache miss; the header is never trusted as the relation identity. Legacy dimension-only
 * fingerprints remain readable for old development bundles, but do not provide this exact
 * content binding.</p>
 *
 * <p>Format (little-endian): {@code "ZJRF" | u32 version=1 | u16 fpLen | fp (UTF-8) | u32 rows |
 * u32 dictSize | 3 × (u32 nnz | int[rows+1] rowOffsets | int[nnz] wireIdx | int[nnz] coeffIdx) |
 * dictSize × 32-byte BE canonical Fr}.</p>
 */
public final class R1CSFlatIO {

    private R1CSFlatIO() {}

    private static final int MAGIC = 0x5A4A5246; // "ZJRF"
    private static final int VERSION = 1;
    private static final byte[] CANONICAL_DOMAIN =
            "zeroj-r1cs-canonical-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final Pattern EXACT_FINGERPRINT = Pattern.compile(
            "c([1-9][0-9]*)-w([1-9][0-9]*)-p(0|[1-9][0-9]*)-r([0-9a-f]{64})");
    private static final Pattern DIMENSION_FINGERPRINT = Pattern.compile(
            "c([1-9][0-9]*)-w([1-9][0-9]*)-p(0|[1-9][0-9]*)(?:-r[0-9a-f]{64})?");
    private static final ValueLayout.OfInt LE_INT =
            ValueLayout.JAVA_INT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN);
    private static final int MAX_DICTIONARY_ENTRIES = 1 << 20;
    private static final BigInteger BLS12_381_SCALAR_MODULUS = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /**
     * SHA-256 commitment to the exact canonical R1CS relation and its wire/public-input
     * dimensions. Unlike the historical {@code c...-w...-p...} label, this distinguishes
     * different equations that happen to have the same dimensions.
     *
     * <p>The digest grammar is streaming and allocation-bounded:
     * {@code domain | u32le rows | u32le wires | u32le public | A | B | C}, where each matrix is
     * encoded row-by-row as
     * {@code u32le termCount | (u32le wire | be32 coefficient)*}. Terms are
     * already sorted by wire in {@link R1CSFlat}. Dictionary indices are deliberately excluded,
     * so equivalent packed dictionaries cannot change circuit identity.</p>
     */
    public static String canonicalSha256(R1CSFlat flat, int numWires, int numPublic) {
        if (flat == null) throw new NullPointerException("flat");
        if (numWires < 1) throw new IllegalArgumentException("numWires must be >= 1");
        if (numPublic < 0 || numPublic >= numWires) {
            throw new IllegalArgumentException("numPublic must be in [0, numWires)");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(CANONICAL_DOMAIN);
            updateInt(digest, flat.rows());
            updateInt(digest, numWires);
            updateInt(digest, numPublic);
            byte[][] dictionary = canonicalDictionary(flat.dictionary());
            updateMatrix(digest, flat.rows(), flat.a(), dictionary, numWires);
            updateMatrix(digest, flat.rows(), flat.b(), dictionary, numWires);
            updateMatrix(digest, flat.rows(), flat.c(), dictionary, numWires);
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static void updateMatrix(
            MessageDigest digest, int rows, R1CSFlat.Matrix matrix,
            byte[][] dictionary, int numWires) {
        int previousEnd = 0;
        for (int row = 0; row < rows; row++) {
            int start = matrix.start(row);
            int end = matrix.end(row);
            if (start != previousEnd || end < start || end > matrix.nnz()) {
                throw new IllegalArgumentException("R1CS matrix has malformed CSR row offsets");
            }
            previousEnd = end;
            updateInt(digest, end - start);
            int previousWire = -1;
            for (int index = start; index < end; index++) {
                int wire = matrix.wire(index);
                if (wire < 0 || wire >= numWires) {
                    throw new IllegalArgumentException(
                            "R1CS matrix wire " + wire + " is outside [0, " + numWires + ")");
                }
                if (wire <= previousWire) {
                    throw new IllegalArgumentException(
                            "R1CS matrix terms must be strictly sorted by wire");
                }
                previousWire = wire;
                updateInt(digest, wire);
                int coefficient = matrix.coeffIndex(index);
                if (coefficient < 0 || coefficient >= dictionary.length) {
                    throw new IllegalArgumentException(
                            "R1CS matrix coefficient index is outside the dictionary");
                }
                digest.update(dictionary[coefficient]);
            }
        }
        if (previousEnd != matrix.nnz()) {
            throw new IllegalArgumentException("R1CS matrix has unreachable trailing terms");
        }
    }

    private static void updateInt(MessageDigest digest, int value) {
        if (value < 0) throw new IllegalArgumentException("canonical R1CS integers must be >= 0");
        digest.update((byte) value);
        digest.update((byte) (value >>> 8));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 24));
    }

    private static byte[][] canonicalDictionary(BigInteger[] values) {
        if (values.length > MAX_DICTIONARY_ENTRIES) {
            throw new IllegalArgumentException("R1CS coefficient dictionary is unreasonably large");
        }
        byte[][] encoded = new byte[values.length][];
        for (int index = 0; index < values.length; index++) {
            encoded[index] = canonicalScalar(values[index]);
        }
        return encoded;
    }

    private static byte[] canonicalScalar(BigInteger value) {
        if (value == null || value.signum() < 0
                || value.compareTo(BLS12_381_SCALAR_MODULUS) >= 0) {
            throw new IllegalArgumentException(
                    "R1CS coefficient is not a canonical BLS12-381 scalar");
        }
        byte[] encoded = new byte[32];
        byte[] raw = value.toByteArray();
        int source = Math.max(0, raw.length - 32);
        System.arraycopy(raw, source, encoded, 32 - (raw.length - source), raw.length - source);
        return encoded;
    }

    /** Write {@code flat} to {@code file} (atomically via a temp sibling). */
    public static void write(R1CSFlat flat, String fingerprint, Path file) throws IOException {
        requireMatchingExactFingerprint(flat, fingerprint);
        byte[] fp = fingerprint.getBytes(StandardCharsets.UTF_8);
        if (fp.length > 0xffff) throw new IllegalArgumentException("fingerprint too long");
        BigInteger[] dict = flat.dictionary();
        byte[][] encodedDictionary = canonicalDictionary(dict);

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
            for (byte[] coefficient : encodedDictionary) buf.put(coefficient);
        }
        Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    }

    /**
     * Does {@code file} contain the exact relation named by {@code expectedFingerprint}?
     *
     * <p>For exact fingerprints this maps and hashes the decoded relation, rather than trusting
     * the copied header. Legacy dimension-only fingerprints can only receive the historical
     * header check because they contain no relation digest.</p>
     */
    public static boolean hasMatching(Path file, String expectedFingerprint) {
        if (parseExactFingerprint(expectedFingerprint) != null) {
            try (Arena arena = Arena.ofConfined()) {
                return readMapped(file, expectedFingerprint, arena) != null;
            } catch (RuntimeException e) {
                return false;
            }
        }
        if (hasExactSuffix(expectedFingerprint)) return false;
        return hasMatchingHeader(file, expectedFingerprint);
    }

    /**
     * Cheap candidate probe used only to preserve witness/constraint memory ordering. This checks
     * the cache envelope and copied header, not the relation digest; callers must subsequently use
     * {@link #readMapped(Path, String, Arena)} before consuming the relation.
     */
    public static boolean hasMatchingHeader(Path file, String expectedFingerprint) {
        if (!Files.isRegularFile(file)) return false;
        if (expectedFingerprint == null) return false;
        byte[] expected = expectedFingerprint.getBytes(StandardCharsets.UTF_8);
        if (expected.length > 0xffff || (hasExactSuffix(expectedFingerprint)
                && parseExactFingerprint(expectedFingerprint) == null)) return false;
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
        try (Arena arena = Arena.ofConfined()) {
            R1CSFlat mapped = readMapped(file, expectedFingerprint, arena);
            if (mapped == null) return null;
            return R1CSFlat.fromArrays(
                    mapped.rows(), copyMatrix(mapped.a(), mapped.rows()),
                    copyMatrix(mapped.b(), mapped.rows()), copyMatrix(mapped.c(), mapped.rows()),
                    mapped.dictionary().clone());
        } catch (RuntimeException e) {
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
        if (!Files.isRegularFile(file) || expectedFingerprint == null || arena == null) return null;
        ExactFingerprint exact = parseExactFingerprint(expectedFingerprint);
        if (exact == null && hasExactSuffix(expectedFingerprint)) return null;
        FingerprintDimensions dimensions = parseFingerprintDimensions(expectedFingerprint);
        byte[] expected = expectedFingerprint.getBytes(StandardCharsets.UTF_8);
        if (expected.length > 0xffff) return null;
        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            long fileSize = ch.size();
            if (fileSize < 18 || fileSize > Integer.MAX_VALUE) return null;
            MemorySegment seg = ch.map(FileChannel.MapMode.READ_ONLY, 0, fileSize, arena);
            long pos = 0;
            if (seg.get(LE_INT, pos) != MAGIC || seg.get(LE_INT, pos + 4) != VERSION) return null;
            pos += 8;
            int fingerprintLength = seg.get(
                    ValueLayout.JAVA_SHORT_UNALIGNED.withOrder(ByteOrder.LITTLE_ENDIAN), pos)
                    & 0xffff;
            pos += 2;
            if (fingerprintLength != expected.length || !fits(pos, fingerprintLength + 8L, fileSize)) {
                return null;
            }
            for (int index = 0; index < expected.length; index++) {
                if (seg.get(ValueLayout.JAVA_BYTE, pos + index) != expected[index]) return null;
            }
            pos += fingerprintLength;
            int rows = seg.get(LE_INT, pos);
            int dictSize = seg.get(LE_INT, pos + 4);
            pos += 8;
            if (rows < 0 || dictSize < 0 || dictSize > MAX_DICTIONARY_ENTRIES) return null;
            if (dimensions != null && (rows != dimensions.constraints()
                    || dimensions.publicInputs() >= dimensions.wires())) return null;

            long offsetBytes = Math.multiplyExact((long) rows + 1L, 4L);
            R1CSFlat.Matrix[] ms = new R1CSFlat.Matrix[3];
            long totalNnz = 0;
            for (int m = 0; m < 3; m++) {
                if (!fits(pos, 4, fileSize)) return null;
                int nnz = seg.get(LE_INT, pos);
                pos += 4;
                if (nnz < 0) return null;
                long indexBytes = Math.multiplyExact((long) nnz, 4L);
                long matrixBytes = Math.addExact(offsetBytes, Math.multiplyExact(indexBytes, 2L));
                if (!fits(pos, matrixBytes, fileSize)) return null;
                ms[m] = new R1CSFlat.SegmentMatrix(
                        seg.asSlice(pos, offsetBytes),
                        seg.asSlice(pos + offsetBytes, indexBytes),
                        seg.asSlice(pos + offsetBytes + indexBytes, indexBytes), nnz);
                if (!validOffsets(ms[m], rows, nnz)) return null;
                pos += matrixBytes;
                totalNnz = Math.addExact(totalNnz, nnz);
            }

            long dictionaryBytes = Math.multiplyExact((long) dictSize, 32L);
            if (dictSize > totalNnz || !fits(pos, dictionaryBytes, fileSize)
                    || pos + dictionaryBytes != fileSize) return null;
            BigInteger[] dict = new BigInteger[dictSize];
            byte[] be32 = new byte[32];
            for (int i = 0; i < dictSize; i++) {
                MemorySegment.copy(seg, pos + (long) i * 32,
                        MemorySegment.ofArray(be32), 0, 32);
                dict[i] = new BigInteger(1, be32);
            }
            int wireLimit = dimensions == null ? Integer.MAX_VALUE : dimensions.wires();
            for (R1CSFlat.Matrix matrix : ms) {
                if (!validIndices(matrix, rows, dictSize, wireLimit)) return null;
            }
            R1CSFlat flat = R1CSFlat.fromArrays(rows, ms[0], ms[1], ms[2], dict);
            return matchingExactFingerprint(flat, expectedFingerprint) ? flat : null;
        } catch (IOException | RuntimeException e) {
            return null; // treat any corruption as a miss
        }
    }

    private static void requireMatchingExactFingerprint(R1CSFlat flat, String fingerprint) {
        if (flat == null) throw new NullPointerException("flat");
        if (fingerprint == null) throw new NullPointerException("fingerprint");
        ExactFingerprint exact = parseExactFingerprint(fingerprint);
        if (exact == null) {
            if (hasExactSuffix(fingerprint)) {
                throw new IllegalArgumentException("malformed exact R1CS fingerprint");
            }
            return;
        }
        if (!matchingExactFingerprint(flat, exact)) {
            throw new IllegalArgumentException(
                    "exact R1CS fingerprint does not match the relation being written");
        }
    }

    private static boolean matchingExactFingerprint(R1CSFlat flat, String fingerprint) {
        ExactFingerprint exact = parseExactFingerprint(fingerprint);
        return exact == null ? !hasExactSuffix(fingerprint) : matchingExactFingerprint(flat, exact);
    }

    private static boolean matchingExactFingerprint(R1CSFlat flat, ExactFingerprint exact) {
        return flat.rows() == exact.constraints()
                && canonicalSha256(flat, exact.wires(), exact.publicInputs()).equals(exact.sha256());
    }

    /** Parses and bounds-checks an exact relation fingerprint, or returns {@code null}. */
    public static ExactFingerprint parseExactFingerprint(String fingerprint) {
        if (fingerprint == null) return null;
        Matcher matcher = EXACT_FINGERPRINT.matcher(fingerprint);
        if (!matcher.matches()) return null;
        try {
            int constraints = Integer.parseInt(matcher.group(1));
            int wires = Integer.parseInt(matcher.group(2));
            int publicInputs = Integer.parseInt(matcher.group(3));
            if (publicInputs >= wires) return null;
            return new ExactFingerprint(constraints, wires, publicInputs, matcher.group(4));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    /** Validated exact circuit dimensions and canonical relation digest. */
    public record ExactFingerprint(int constraints, int wires, int publicInputs, String sha256) {}

    private static boolean hasExactSuffix(String fingerprint) {
        return fingerprint != null && fingerprint.contains("-r");
    }

    private static FingerprintDimensions parseFingerprintDimensions(String fingerprint) {
        if (fingerprint == null) return null;
        Matcher matcher = DIMENSION_FINGERPRINT.matcher(fingerprint);
        if (!matcher.matches()) return null;
        try {
            int constraints = Integer.parseInt(matcher.group(1));
            int wires = Integer.parseInt(matcher.group(2));
            int publicInputs = Integer.parseInt(matcher.group(3));
            if (publicInputs >= wires) return null;
            return new FingerprintDimensions(constraints, wires, publicInputs);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private record FingerprintDimensions(int constraints, int wires, int publicInputs) {}

    private static boolean fits(long position, long bytes, long limit) {
        return position >= 0 && bytes >= 0 && position <= limit && bytes <= limit - position;
    }

    private static boolean validOffsets(R1CSFlat.Matrix matrix, int rows, int nnz) {
        int previous = 0;
        for (int row = 0; row < rows; row++) {
            int start = matrix.start(row);
            int end = matrix.end(row);
            if (start != previous || end < start || end > nnz) return false;
            previous = end;
        }
        return previous == nnz;
    }

    private static boolean validIndices(
            R1CSFlat.Matrix matrix, int rows, int dictSize, int wireLimit) {
        for (int row = 0; row < rows; row++) {
            int previousWire = -1;
            for (int index = matrix.start(row); index < matrix.end(row); index++) {
                int wire = matrix.wire(index);
                int coefficient = matrix.coeffIndex(index);
                if (wire < 0 || wire >= wireLimit || wire <= previousWire
                        || coefficient < 0 || coefficient >= dictSize) return false;
                previousWire = wire;
            }
        }
        return true;
    }

    private static R1CSFlat.Matrix copyMatrix(R1CSFlat.Matrix matrix, int rows) {
        int[] offsets = new int[rows + 1];
        int[] wires = new int[matrix.nnz()];
        int[] coefficients = new int[matrix.nnz()];
        for (int row = 0; row < rows; row++) offsets[row] = matrix.start(row);
        offsets[rows] = rows == 0 ? 0 : matrix.end(rows - 1);
        for (int index = 0; index < matrix.nnz(); index++) {
            wires[index] = matrix.wire(index);
            coefficients[index] = matrix.coeffIndex(index);
        }
        return new R1CSFlat.HeapMatrix(offsets, wires, coefficients);
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
