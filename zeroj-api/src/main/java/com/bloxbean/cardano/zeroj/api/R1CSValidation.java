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
 * secret is read. The one exception is {@link #requirePublicWiresConstrained}, which needs to
 * know whether a coefficient is zero modulo the caller-supplied scalar-field order.</p>
 *
 * <p><b>Public-wire binding (ADR-0045, issue #52).</b> The Groth16 verification key entry for
 * public wire {@code s} is {@code IC[s] = (beta*u_s + alpha*v_s + w_s)/gamma * G1}. When wire
 * {@code s} carries no nonzero coefficient in any row, {@code u_s = v_s = w_s = 0} and
 * {@code IC[s]} is the point at infinity, which the ADR-0025 verifier profile rejects on every
 * provider and which would leave public input {@code s} unbound by the verification equation.
 * {@link #requirePublicWiresConstrained} rejects such a relation at the setup ingress with the
 * wire named. The rule covers the constant wire {@code 0} too: a relation with no constant term
 * yields {@code IC[0] = infinity}, which is rejected the same way.</p>
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

    /**
     * Require every public wire {@code s} in {@code [0, numPublic]} (the constant wire {@code 0}
     * included) to carry at least one coefficient that is nonzero modulo {@code modulus} in some
     * {@code A}, {@code B}, or {@code C} row (ADR-0045 invariant S1).
     *
     * <p>The scan stops as soon as every public wire is bound; rows after that point are not
     * inspected (run {@link #requireWireIndices} first for full structural validation).</p>
     *
     * @param constraints the relation; a lazy {@link R1CSFlat#asList()} view is accepted
     * @param numPublic   number of public inputs (wires {@code 1..numPublic})
     * @param modulus     the scalar-field order used to decide whether a coefficient is zero
     * @throws IllegalArgumentException naming the first unbound public wire
     */
    public static void requirePublicWiresConstrained(List<R1CSConstraint> constraints, int numPublic,
                                                     BigInteger modulus) {
        if (constraints == null) throw new IllegalArgumentException("constraints must not be null");
        requireModulus(modulus);
        if (numPublic < 0) throw new IllegalArgumentException("numPublic must be >= 0 (got " + numPublic + ")");
        boolean[] bound = new boolean[numPublic + 1];
        int remaining = numPublic + 1;
        int rows = constraints.size();
        for (int row = 0; row < rows && remaining > 0; row++) {
            R1CSConstraint c = constraints.get(row);
            if (c == null) throw new IllegalArgumentException("R1CS row " + row + " is null");
            remaining -= markBound(bound, c.a(), modulus, "A", row);
            remaining -= markBound(bound, c.b(), modulus, "B", row);
            remaining -= markBound(bound, c.c(), modulus, "C", row);
        }
        requireAllBound(bound);
    }

    /**
     * CSR form of {@link #requirePublicWiresConstrained(List, int, BigInteger)}. The relation is
     * assumed to have passed {@link #requireWireIndices(R1CSFlat, int)} (CSR structure and wire
     * ranges); dictionary entries are reduced modulo {@code modulus} to decide zero-ness.
     */
    public static void requirePublicWiresConstrained(R1CSFlat flat, int numPublic, BigInteger modulus) {
        if (flat == null) throw new IllegalArgumentException("constraints must not be null");
        requireModulus(modulus);
        if (numPublic < 0) throw new IllegalArgumentException("numPublic must be >= 0 (got " + numPublic + ")");
        BigInteger[] dictionary = flat.dictionary();
        if (dictionary == null) throw new IllegalArgumentException("R1CS coefficient dictionary is null");
        boolean[] nonzero = new boolean[dictionary.length];
        for (int i = 0; i < dictionary.length; i++) {
            if (dictionary[i] == null) {
                throw new IllegalArgumentException("R1CS coefficient dictionary entry " + i + " is null");
            }
            nonzero[i] = isNonzeroModulo(dictionary[i], modulus);
        }
        boolean[] bound = new boolean[numPublic + 1];
        int remaining = numPublic + 1;
        remaining -= markBound(bound, flat.a(), nonzero, remaining);
        if (remaining > 0) remaining -= markBound(bound, flat.b(), nonzero, remaining);
        if (remaining > 0) markBound(bound, flat.c(), nonzero, remaining);
        requireAllBound(bound);
    }

    private static void requireModulus(BigInteger modulus) {
        if (modulus == null || modulus.signum() <= 0) {
            throw new IllegalArgumentException("modulus must be a positive scalar-field order");
        }
    }

    /** Marks public wires with a nonzero term in {@code lc}; returns how many became newly bound. */
    private static int markBound(boolean[] bound, Map<Integer, BigInteger> lc, BigInteger modulus,
                                 String matrix, int row) {
        if (lc == null) throw new IllegalArgumentException("R1CS " + matrix + " row " + row + " is null");
        int newlyBound = 0;
        for (Map.Entry<Integer, BigInteger> term : lc.entrySet()) {
            Integer wire = term.getKey();
            BigInteger coefficient = term.getValue();
            if (wire == null || coefficient == null) {
                throw new IllegalArgumentException("R1CS " + matrix + " row " + row
                        + " has a null wire or coefficient");
            }
            if (wire < 0 || wire >= bound.length || bound[wire]) continue;
            if (isNonzeroModulo(coefficient, modulus)) {
                bound[wire] = true;
                newlyBound++;
            }
        }
        return newlyBound;
    }

    /** {@code c mod modulus != 0}, without the division for the common canonical {@code 0 < c < modulus}. */
    private static boolean isNonzeroModulo(BigInteger c, BigInteger modulus) {
        int sign = c.signum();
        if (sign == 0) return false;
        if (sign > 0 && c.compareTo(modulus) < 0) return true;
        return c.mod(modulus).signum() != 0;
    }

    /** CSR variant: walks every stored term of {@code m}; stops early once all wires are bound. */
    private static int markBound(boolean[] bound, R1CSFlat.Matrix m, boolean[] nonzero, int remaining) {
        if (m == null) throw new IllegalArgumentException("R1CS matrix is null");
        int newlyBound = 0;
        int nnz = m.nnz();
        for (int k = 0; k < nnz && newlyBound < remaining; k++) {
            int wire = m.wire(k);
            if (wire < 0 || wire >= bound.length || bound[wire]) continue;
            int coefficient = m.coeffIndex(k);
            if (coefficient < 0 || coefficient >= nonzero.length) {
                throw new IllegalArgumentException("R1CS term " + k + " has coefficient index " + coefficient
                        + " outside the dictionary (size " + nonzero.length + ")");
            }
            if (nonzero[coefficient]) {
                bound[wire] = true;
                newlyBound++;
            }
        }
        return newlyBound;
    }

    private static void requireAllBound(boolean[] bound) {
        for (int s = 0; s < bound.length; s++) {
            if (!bound[s]) throw unboundPublicWire(s, bound.length - 1);
        }
    }

    private static IllegalArgumentException unboundPublicWire(int wire, int numPublic) {
        if (wire == 0) {
            return new IllegalArgumentException("R1CS constant wire 0 (ONE) is not referenced by any constraint:"
                    + " the relation has no constant term, so IC[0] would be the point at infinity, which every"
                    + " Groth16 verifier profile rejects (ADR-0045). Add a row that references wire 0,"
                    + " e.g. 1 * 1 = 1.");
        }
        return new IllegalArgumentException("R1CS public wire " + wire + " (public input " + wire + " of "
                + numPublic + ") is not referenced by any constraint: IC[" + wire + "] would be the point at"
                + " infinity and the public input would be unbound by the verification equation (ADR-0045)."
                + " Constrain the input in the circuit or remove it from the public inputs.");
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
