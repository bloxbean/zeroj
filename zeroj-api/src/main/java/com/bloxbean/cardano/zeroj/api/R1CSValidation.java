package com.bloxbean.cardano.zeroj.api;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/**
 * Fail-closed shape checks for a caller-supplied R1CS relation at the Groth16 setup and prove
 * trust boundary (issue #46).
 *
 * <p>A relation's wire indices are untrusted input. The direct setup and prover paths used to
 * skip any term whose wire fell outside {@code [0, numWires)}, which silently changed the
 * relation being set up or proved: a mistyped index or an undersized {@code numWires} produced a
 * key and verifying proofs for a weaker relation than the one written. Every public setup/prove
 * ingress now runs these checks once, before any QAP, FFT, or MSM work, so a malformed relation
 * is rejected instead of weakened. The imported ({@code R1CSImporter}) and canonical-cache
 * ({@code R1CSFlatIO}) paths already enforced the same bounds; this class gives the direct
 * {@link R1CSConstraint} list and {@link R1CSFlat} paths identical semantics.</p>
 *
 * <p>Only shape is checked: dimensions, wire ranges, and CSR structure. Coefficient values are
 * not interpreted (the consumers reduce them modulo the scalar field), and no witness scalar or
 * secret is read.</p>
 */
public final class R1CSValidation {

    private R1CSValidation() {}

    /**
     * Require {@code numWires >= 1} (wire 0 is the constant ONE) and
     * {@code 0 <= numPublic < numWires}.
     *
     * @throws IllegalArgumentException when either bound is violated
     */
    public static void requireDimensions(int numWires, int numPublic) {
        requireNumWires(numWires);
        if (numPublic < 0 || numPublic >= numWires) {
            throw new IllegalArgumentException("numPublic must be in [0, numWires) (got numPublic="
                    + numPublic + ", numWires=" + numWires + ")");
        }
    }

    /**
     * Require every {@code A}/{@code B}/{@code C} term of every constraint to reference a wire in
     * {@code [0, numWires)}, with no null rows or coefficients.
     *
     * @param constraints the relation; a lazy {@link R1CSFlat#asList()} view is accepted
     * @param numWires    the relation dimension at setup, or the witness length at prove time
     * @throws IllegalArgumentException naming the matrix, row, and offending wire
     */
    public static void requireWireIndices(List<R1CSConstraint> constraints, int numWires) {
        if (constraints == null) throw new IllegalArgumentException("constraints must not be null");
        requireNumWires(numWires);
        int rows = constraints.size();
        for (int row = 0; row < rows; row++) {
            R1CSConstraint c = constraints.get(row);
            if (c == null) throw new IllegalArgumentException("R1CS row " + row + " is null");
            requireRow("A", row, c.a(), numWires);
            requireRow("B", row, c.b(), numWires);
            requireRow("C", row, c.c(), numWires);
        }
    }

    /**
     * Require the packed relation to be structurally well formed (monotone CSR row offsets that
     * cover exactly the stored terms, coefficient indices inside the dictionary) and every term
     * to reference a wire in {@code [0, numWires)}.
     *
     * @param flat     the relation (heap-backed or memory-mapped)
     * @param numWires the relation dimension at setup, or the witness length at prove time
     * @throws IllegalArgumentException naming the matrix, row, and offending wire or index
     */
    public static void requireWireIndices(R1CSFlat flat, int numWires) {
        if (flat == null) throw new IllegalArgumentException("constraints must not be null");
        requireNumWires(numWires);
        int rows = flat.rows();
        if (rows < 0) throw new IllegalArgumentException("R1CS row count must be >= 0 (got " + rows + ")");
        BigInteger[] dictionary = flat.dictionary();
        if (dictionary == null) throw new IllegalArgumentException("R1CS coefficient dictionary is null");
        requireMatrix("A", flat.a(), rows, dictionary.length, numWires);
        requireMatrix("B", flat.b(), rows, dictionary.length, numWires);
        requireMatrix("C", flat.c(), rows, dictionary.length, numWires);
    }

    private static void requireNumWires(int numWires) {
        if (numWires < 1) throw new IllegalArgumentException("numWires must be >= 1 (got " + numWires + ")");
    }

    private static void requireRow(String matrix, int row, Map<Integer, BigInteger> lc, int numWires) {
        if (lc == null) throw new IllegalArgumentException("R1CS " + matrix + " row " + row + " is null");
        for (Map.Entry<Integer, BigInteger> term : lc.entrySet()) {
            Integer wire = term.getKey();
            if (wire == null || wire < 0 || wire >= numWires) throw outOfRange(matrix, row, wire, numWires);
            if (term.getValue() == null) {
                throw new IllegalArgumentException("R1CS " + matrix + " row " + row + " wire " + wire
                        + " has a null coefficient");
            }
        }
    }

    private static void requireMatrix(String matrix, R1CSFlat.Matrix m, int rows, int dictSize, int numWires) {
        if (m == null) throw new IllegalArgumentException("R1CS " + matrix + " matrix is null");
        int nnz = m.nnz();
        if (nnz < 0) throw new IllegalArgumentException("R1CS " + matrix + " matrix has a negative term count");
        int previousEnd = 0;
        for (int row = 0; row < rows; row++) {
            int start = m.start(row);
            int end = m.end(row);
            if (start != previousEnd || end < start || end > nnz) {
                throw new IllegalArgumentException("R1CS " + matrix + " matrix has malformed CSR row offsets at row "
                        + row + " (start=" + start + ", end=" + end + ", nnz=" + nnz + ")");
            }
            for (int k = start; k < end; k++) {
                int wire = m.wire(k);
                if (wire < 0 || wire >= numWires) throw outOfRange(matrix, row, wire, numWires);
                int coefficient = m.coeffIndex(k);
                if (coefficient < 0 || coefficient >= dictSize) {
                    throw new IllegalArgumentException("R1CS " + matrix + " matrix row " + row
                            + " has coefficient index " + coefficient + " outside the dictionary (size "
                            + dictSize + ")");
                }
            }
            previousEnd = end;
        }
        if (previousEnd != nnz) {
            throw new IllegalArgumentException("R1CS " + matrix + " matrix has " + (nnz - previousEnd)
                    + " unreachable trailing terms");
        }
    }

    private static IllegalArgumentException outOfRange(String matrix, int row, Integer wire, int numWires) {
        return new IllegalArgumentException("R1CS " + matrix + " row " + row + " references wire " + wire
                + " outside [0, " + numWires + ")");
    }
}
