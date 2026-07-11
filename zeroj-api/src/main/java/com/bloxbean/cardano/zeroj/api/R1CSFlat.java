package com.bloxbean.cardano.zeroj.api;

import java.math.BigInteger;
import java.util.AbstractList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.RandomAccess;

/**
 * Packed CSR (compressed sparse row) storage for the three R1CS matrices (ADR-0034 M2).
 *
 * <p>The map-based {@link R1CSConstraint} representation costs ~350–400 B per non-zero term at
 * scale (HashMap node + boxed key + BigInteger); at 19M constraints that is the dominant share of
 * the compile/prove heap (measured ~7.4 GB). This packs each matrix into three int arrays —
 * {@code rowOffsets}, {@code wireIdx}, {@code coeffIdx} — plus one shared <b>coefficient
 * dictionary</b>: circuits draw their coefficients from a small set of distinct values (±1,
 * powers of two, gadget constants), so each term stores a 4-byte dictionary index instead of a
 * boxed BigInteger. ~12 B per term, ~50× smaller.</p>
 *
 * <p>Terms within a row are sorted by wire index (deterministic, order-independent for the
 * modular sums that consume them). {@link #asList()} adapts back to
 * {@code List<R1CSConstraint>} lazily, so map-based consumers (setup, exporters, importers)
 * keep working unchanged.</p>
 */
public final class R1CSFlat {

    /** One CSR matrix: row {@code i}'s terms are entries {@code rowOffsets[i] .. rowOffsets[i+1]}. */
    public sealed interface Matrix permits HeapMatrix, SegmentMatrix {
        int start(int row);
        int end(int row);
        int wire(int k);
        int coeffIndex(int k);
        int nnz();
    }

    /** On-heap CSR matrix (fresh compiles, heap-loaded caches). */
    public static final class HeapMatrix implements Matrix {
        private final int[] rowOffsets; // rows + 1
        private final int[] wireIdx;    // nnz
        private final int[] coeffIdx;   // nnz, index into the shared dictionary

        HeapMatrix(int[] rowOffsets, int[] wireIdx, int[] coeffIdx) {
            this.rowOffsets = rowOffsets;
            this.wireIdx = wireIdx;
            this.coeffIdx = coeffIdx;
        }

        @Override public int start(int row) { return rowOffsets[row]; }
        @Override public int end(int row) { return rowOffsets[row + 1]; }
        @Override public int wire(int k) { return wireIdx[k]; }
        @Override public int coeffIndex(int k) { return coeffIdx[k]; }
        @Override public int nnz() { return wireIdx.length; }

        // raw arrays for serialization (R1CSFlatIO)
        int[] rowOffsets() { return rowOffsets; }
        int[] wireIdx() { return wireIdx; }
        int[] coeffIdx() { return coeffIdx; }
    }

    /**
     * CSR matrix over slices of an mmap'd {@code r1cs.bin} (ADR-0034 M6a) — the constraint
     * arrays stay file-backed/off-heap, like the proving key. Little-endian ints, unaligned
     * (the file header's variable-length fingerprint shifts the array offsets).
     */
    public static final class SegmentMatrix implements Matrix {
        private static final java.lang.foreign.ValueLayout.OfInt LE_INT =
                java.lang.foreign.ValueLayout.JAVA_INT_UNALIGNED.withOrder(java.nio.ByteOrder.LITTLE_ENDIAN);

        private final java.lang.foreign.MemorySegment rowOffsets, wireIdx, coeffIdx;
        private final int nnz;

        SegmentMatrix(java.lang.foreign.MemorySegment rowOffsets,
                      java.lang.foreign.MemorySegment wireIdx,
                      java.lang.foreign.MemorySegment coeffIdx, int nnz) {
            this.rowOffsets = rowOffsets;
            this.wireIdx = wireIdx;
            this.coeffIdx = coeffIdx;
            this.nnz = nnz;
        }

        @Override public int start(int row) { return rowOffsets.get(LE_INT, (long) row * 4); }
        @Override public int end(int row) { return rowOffsets.get(LE_INT, (long) (row + 1) * 4); }
        @Override public int wire(int k) { return wireIdx.get(LE_INT, (long) k * 4); }
        @Override public int coeffIndex(int k) { return coeffIdx.get(LE_INT, (long) k * 4); }
        @Override public int nnz() { return nnz; }
    }

    /** Reconstruct from CSR matrices (deserialization — see {@code R1CSFlatIO}). */
    static R1CSFlat fromArrays(int rows, Matrix a, Matrix b, Matrix c, BigInteger[] dict) {
        return new R1CSFlat(rows, a, b, c, dict);
    }

    private final int rows;
    private final Matrix a, b, c;
    private final BigInteger[] dict;

    private R1CSFlat(int rows, Matrix a, Matrix b, Matrix c, BigInteger[] dict) {
        this.rows = rows;
        this.a = a;
        this.b = b;
        this.c = c;
        this.dict = dict;
    }

    public int rows() { return rows; }
    public Matrix a() { return a; }
    public Matrix b() { return b; }
    public Matrix c() { return c; }

    /** The distinct coefficient values; term {@code k}'s coefficient is {@code dict[coeffIndex(k)]}. */
    public BigInteger[] dictionary() { return dict; }

    public BigInteger coeff(Matrix m, int k) { return dict[m.coeffIndex(k)]; }

    /** Materialize row {@code i} as a map-based {@link R1CSConstraint} (compatibility form). */
    public R1CSConstraint row(int i) {
        return new R1CSConstraint(rowMap(a, i), rowMap(b, i), rowMap(c, i));
    }

    private Map<Integer, BigInteger> rowMap(Matrix m, int i) {
        int s = m.start(i), e = m.end(i);
        if (s == e) return Map.of();
        Map<Integer, BigInteger> out = LinkedHashMap.newLinkedHashMap(e - s);
        for (int k = s; k < e; k++) out.put(m.wire(k), dict[m.coeffIndex(k)]);
        return out;
    }

    /**
     * A lazy {@code List<R1CSConstraint>} view — rows materialize per access, nothing is retained.
     * Keeps map-based consumers (Groth16 setup, {@code R1csExporter}, tests) working unchanged.
     */
    public List<R1CSConstraint> asList() {
        final class View extends AbstractList<R1CSConstraint> implements RandomAccess {
            @Override public int size() { return rows; }
            @Override public R1CSConstraint get(int i) { return row(i); }
        }
        return new View();
    }

    public static Builder builder() { return new Builder(); }

    /** Streaming builder: {@link #add} one constraint at a time; chunked storage (no humongous grow-copies). */
    public static final class Builder {
        private final IntBuf aOff = new IntBuf(), aWire = new IntBuf(), aCoeff = new IntBuf();
        private final IntBuf bOff = new IntBuf(), bWire = new IntBuf(), bCoeff = new IntBuf();
        private final IntBuf cOff = new IntBuf(), cWire = new IntBuf(), cCoeff = new IntBuf();
        private final Map<BigInteger, Integer> dictIndex = new HashMap<>();
        private final java.util.ArrayList<BigInteger> dictValues = new java.util.ArrayList<>();
        private int rows;

        private Builder() { aOff.add(0); bOff.add(0); cOff.add(0); }

        /** Append one constraint; the maps are copied into packed form and not retained. */
        public void add(Map<Integer, BigInteger> a, Map<Integer, BigInteger> b, Map<Integer, BigInteger> c) {
            appendRow(a, aOff, aWire, aCoeff);
            appendRow(b, bOff, bWire, bCoeff);
            appendRow(c, cOff, cWire, cCoeff);
            rows++;
        }

        public int rows() { return rows; }

        private void appendRow(Map<Integer, BigInteger> row, IntBuf off, IntBuf wire, IntBuf coeff) {
            int n = row.size();
            if (n == 1) { // dominant case (C rows, base-wire terms) — skip the sort machinery
                var e = row.entrySet().iterator().next();
                wire.add(e.getKey());
                coeff.add(dictIdx(e.getValue()));
            } else if (n > 1) {
                int[] wires = new int[n];
                int i = 0;
                for (Integer w : row.keySet()) wires[i++] = w;
                Arrays.sort(wires);
                for (int w : wires) {
                    wire.add(w);
                    coeff.add(dictIdx(row.get(w)));
                }
            }
            off.add(wire.size());
        }

        private int dictIdx(BigInteger v) {
            Integer idx = dictIndex.get(v);
            if (idx != null) return idx;
            int next = dictValues.size();
            dictIndex.put(v, next);
            dictValues.add(v);
            return next;
        }

        public R1CSFlat build() {
            var flat = new R1CSFlat(rows,
                    new HeapMatrix(aOff.toArray(), aWire.toArray(), aCoeff.toArray()),
                    new HeapMatrix(bOff.toArray(), bWire.toArray(), bCoeff.toArray()),
                    new HeapMatrix(cOff.toArray(), cWire.toArray(), cCoeff.toArray()),
                    dictValues.toArray(new BigInteger[0]));
            dictIndex.clear();
            return flat;
        }
    }

    /** Growable int storage in 4 MB chunks — appends never re-copy what's already written. */
    private static final class IntBuf {
        private static final int SHIFT = 20, CAP = 1 << SHIFT, MASK = CAP - 1;
        private int[][] chunks = new int[16][];
        private int n;

        void add(int v) {
            int c = n >>> SHIFT;
            if (c == chunks.length) chunks = Arrays.copyOf(chunks, chunks.length * 2);
            if (chunks[c] == null) chunks[c] = new int[CAP];
            chunks[c][n & MASK] = v;
            n++;
        }

        int size() { return n; }

        int[] toArray() {
            int[] out = new int[n];
            for (int c = 0; (long) c * CAP < n; c++)
                System.arraycopy(chunks[c], 0, out, c * CAP, Math.min(CAP, n - c * CAP));
            return out;
        }
    }
}
