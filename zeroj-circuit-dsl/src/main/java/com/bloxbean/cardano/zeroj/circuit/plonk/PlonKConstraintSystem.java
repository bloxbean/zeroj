package com.bloxbean.cardano.zeroj.circuit.plonk;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.List;

/**
 * A compiled PlonK constraint system — gate table + copy constraints (permutation).
 *
 * <p>Each gate row enforces: qL*a + qR*b + qO*c + qM*(a*b) + qC = 0</p>
 */
public record PlonKConstraintSystem(
        FieldConfig fieldConfig,
        int numGates,
        int numPublicInputs,
        List<GateRow> gateRows,
        int[] sigmaA, int[] sigmaB, int[] sigmaC,
        int numWires,
        BigInteger k1, BigInteger k2
) {
    /**
     * A single PlonK gate row.
     */
    public record GateRow(
            BigInteger qL, BigInteger qR, BigInteger qO, BigInteger qM, BigInteger qC,
            int wireA, int wireB, int wireC
    ) {}

    public int domainSize() {
        // Pad to next power of 2
        int n = 1;
        while (n < numGates) n <<= 1;
        return n;
    }
}
