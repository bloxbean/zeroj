package org.zeroj.circuit.r1cs;

import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.R1CSFlat;
import org.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * A compiled R1CS (Rank-1 Constraint System) for Groth16 proving.
 *
 * <p>Each constraint has the form: (A · w) × (B · w) = (C · w)
 * where A, B, C are sparse vectors of field coefficients and w is the witness.</p>
 *
 * <p>Since ADR-0034 the compiler stores the matrices packed ({@link R1CSFlat}, ~12 B/term);
 * {@link #constraints()} is a lazy map-based view over it for compatibility. Memory-sensitive
 * consumers (the Groth16 prover's H computation) should read {@link #flat()} directly.</p>
 */
public record R1CSConstraintSystem(
        FieldConfig fieldConfig,
        int numWires,
        int numPublicInputs,
        int numPrivateInputs,
        List<R1CSConstraint> constraints,
        R1CSFlat flat
) {
    /** Legacy shape (pre-ADR-0034): a materialized constraint list, no packed form. */
    public R1CSConstraintSystem(FieldConfig fieldConfig, int numWires, int numPublicInputs,
                                int numPrivateInputs, List<R1CSConstraint> constraints) {
        this(fieldConfig, numWires, numPublicInputs, numPrivateInputs, constraints, null);
    }

    public BigInteger prime() { return fieldConfig.prime(); }
    public int numConstraints() { return constraints.size(); }

    /**
     * Curve-generic R1CS witness verifier: checks wire count, wire 0 == 1, canonical field
     * range {@code [0, prime)} on every witness entry, and every constraint
     * {@code (A · w) * (B · w) ≡ (C · w) (mod prime)}.
     *
     * @throws IllegalArgumentException if the witness is malformed or violates any constraint
     */
    public void verifyWitness(BigInteger[] witness) {
        Objects.requireNonNull(witness, "witness");
        if (witness.length != numWires) {
            throw new IllegalArgumentException(
                    "witness.length (" + witness.length + ") must match numWires (" + numWires + ")");
        }
        BigInteger mod = prime();
        validateWitnessElements(witness, mod);
        if (flat != null) {
            int rows = flat.rows();
            for (int i = 0; i < rows; i++) {
                BigInteger aVal = evalFlatRow(flat, flat.a(), i, witness, mod);
                BigInteger bVal = evalFlatRow(flat, flat.b(), i, witness, mod);
                BigInteger cVal = evalFlatRow(flat, flat.c(), i, witness, mod);
                BigInteger lhs = aVal.multiply(bVal).mod(mod);
                if (!lhs.equals(cVal)) {
                    throw new IllegalArgumentException(
                            "Witness does not satisfy R1CS constraint " + i);
                }
            }
        } else {
            verifyWitnessConstraints(constraints, witness, constraints.size(), mod);
        }
    }

    /**
     * Curve-generic R1CS witness verification against an explicit constraint list and field.
     */
    public static void verifyWitness(List<R1CSConstraint> constraints, BigInteger[] witness, FieldConfig field) {
        Objects.requireNonNull(field, "field");
        verifyWitness(constraints, witness, field.prime(), constraints != null ? constraints.size() : 0);
    }

    /**
     * Curve-generic R1CS witness verification against the first {@code numConstraints} entries of
     * {@code constraints} modulo {@code prime}.
     */
    public static void verifyWitness(
            List<R1CSConstraint> constraints,
            BigInteger[] witness,
            BigInteger prime,
            int numConstraints) {
        Objects.requireNonNull(constraints, "constraints");
        Objects.requireNonNull(witness, "witness");
        Objects.requireNonNull(prime, "prime");
        if (prime.signum() <= 0) {
            throw new IllegalArgumentException("prime must be positive");
        }
        if (numConstraints < 0 || numConstraints > constraints.size()) {
            throw new IllegalArgumentException(
                    "numConstraints (" + numConstraints + ") out of bounds for size " + constraints.size());
        }
        validateWitnessElements(witness, prime);
        verifyWitnessConstraints(constraints, witness, numConstraints, prime);
    }

    private static void validateWitnessElements(BigInteger[] witness, BigInteger mod) {
        if (witness.length == 0) {
            throw new IllegalArgumentException("Witness must not be empty");
        }
        for (int i = 0; i < witness.length; i++) {
            BigInteger v = witness[i];
            if (v == null || v.signum() < 0 || v.compareTo(mod) >= 0) {
                throw new IllegalArgumentException(
                        "Witness entry at wire " + i + " is not a canonical field element in [0, p)");
            }
        }
        if (!BigInteger.ONE.equals(witness[0])) {
            throw new IllegalArgumentException(
                    "witness[0] must be 1 (the constant wire)");
        }
    }

    private static void verifyWitnessConstraints(
            List<R1CSConstraint> constraints,
            BigInteger[] witness,
            int numConstraints,
            BigInteger mod) {
        for (int i = 0; i < numConstraints; i++) {
            R1CSConstraint c = Objects.requireNonNull(constraints.get(i), "constraints[" + i + "]");
            if (c.a().isEmpty() && c.b().isEmpty() && c.c().isEmpty()) continue;
            BigInteger aVal = evalLinearCombination(c.a(), witness, mod);
            BigInteger bVal = evalLinearCombination(c.b(), witness, mod);
            BigInteger cVal = evalLinearCombination(c.c(), witness, mod);
            BigInteger lhs = aVal.multiply(bVal).mod(mod);
            if (!lhs.equals(cVal)) {
                throw new IllegalArgumentException(
                        "Witness does not satisfy R1CS constraint " + i);
            }
        }
    }

    private static BigInteger evalFlatRow(
            R1CSFlat flat, R1CSFlat.Matrix m, int row, BigInteger[] witness, BigInteger mod) {
        BigInteger sum = BigInteger.ZERO;
        int end = m.end(row);
        for (int k = m.start(row); k < end; k++) {
            int wireIdx = m.wire(k);
            if (wireIdx < 0 || wireIdx >= witness.length) {
                throw new IllegalArgumentException(
                        "Constraint references wire " + wireIdx
                                + " outside witness length " + witness.length);
            }
            BigInteger coeff = flat.coeff(m, k);
            if (coeff.signum() != 0) {
                sum = sum.add(coeff.multiply(witness[wireIdx]));
            }
        }
        return sum.mod(mod);
    }

    private static BigInteger evalLinearCombination(
            Map<Integer, BigInteger> lc, BigInteger[] witness, BigInteger mod) {
        BigInteger sum = BigInteger.ZERO;
        for (var entry : lc.entrySet()) {
            int wireIdx = entry.getKey();
            if (wireIdx < 0 || wireIdx >= witness.length) {
                throw new IllegalArgumentException(
                        "Constraint references wire " + wireIdx
                                + " outside witness length " + witness.length);
            }
            BigInteger coeff = Objects.requireNonNull(entry.getValue(), "coefficient");
            if (coeff.signum() != 0) {
                sum = sum.add(coeff.multiply(witness[wireIdx]));
            }
        }
        return sum.mod(mod);
    }
}
