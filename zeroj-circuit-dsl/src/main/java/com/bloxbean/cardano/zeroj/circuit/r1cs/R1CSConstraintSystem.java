package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.List;

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
}
