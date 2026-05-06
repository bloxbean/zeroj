package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.List;

/**
 * A compiled R1CS (Rank-1 Constraint System) for Groth16 proving.
 *
 * <p>Each constraint has the form: (A · w) × (B · w) = (C · w)
 * where A, B, C are sparse vectors of field coefficients and w is the witness.</p>
 */
public record R1CSConstraintSystem(
        FieldConfig fieldConfig,
        int numWires,
        int numPublicInputs,
        int numPrivateInputs,
        List<R1CSConstraint> constraints
) {
    public BigInteger prime() { return fieldConfig.prime(); }
    public int numConstraints() { return constraints.size(); }
}
