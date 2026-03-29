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

    /**
     * Extend a base witness to include values for virtual intermediate wires
     * created during LinComb chaining.
     *
     * <p>The base witness has values for wires 0..baseLen-1 from the constraint graph.
     * Virtual wires (baseLen..numWires-1) are computed by evaluating gate rows in order:
     * for each row where wireC &ge; baseLen, compute c = (qL*a + qR*b + qM*a*b + qC) / (-qO).</p>
     */
    public BigInteger[] extendWitness(BigInteger[] baseWitness) {
        if (numWires <= baseWitness.length) return baseWitness;
        BigInteger p = fieldConfig.prime();
        BigInteger[] extended = new BigInteger[numWires];
        System.arraycopy(baseWitness, 0, extended, 0, baseWitness.length);
        // Virtual wires are null until computed
        // Compute virtual wire values from gate rows in order
        for (var row : gateRows) {
            if (row.wireC() >= baseWitness.length && extended[row.wireC()] == null) {
                BigInteger a = extended[row.wireA()];
                BigInteger b = extended[row.wireB()];
                // qL*a + qR*b + qM*a*b + qC + qO*c = 0  →  c = -(qL*a + qR*b + qM*a*b + qC) / qO
                BigInteger sum = row.qL().multiply(a)
                        .add(row.qR().multiply(b))
                        .add(row.qM().multiply(a).multiply(b))
                        .add(row.qC())
                        .mod(p);
                // qO is always NEG_ONE (p-1) for these rows, so c = sum
                BigInteger negQO = row.qO().negate().mod(p);
                BigInteger c = sum.multiply(negQO.modInverse(p)).mod(p);
                extended[row.wireC()] = c;
            }
        }
        return extended;
    }
}
