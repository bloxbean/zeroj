package com.bloxbean.cardano.zeroj.circuit.plonk;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.List;

/**
 * A compiled PlonK constraint system — gate table + copy constraints (permutation).
 *
 * <p>Each gate row enforces: qL*a + qR*b + qO*c + qM*(a*b) + qC = 0</p>
 *
 * <p>Follows the snarkjs PlonK convention:</p>
 * <ul>
 *   <li>Public input rows come first (one per public input, with qL=1)</li>
 *   <li>Virtual wire computations are tracked as separate {@link Addition} records</li>
 *   <li>Selector signs in reduction gates: qL=-coeff, qR=-coeff, qO=+1 (output positive on C)</li>
 * </ul>
 */
public record PlonKConstraintSystem(
        FieldConfig fieldConfig,
        int numGates,
        int numPublicInputs,
        List<GateRow> gateRows,
        int[] sigmaA, int[] sigmaB, int[] sigmaC,
        int numWires,
        BigInteger k1, BigInteger k2,
        List<Addition> additions
) {
    /**
     * A single PlonK gate row.
     */
    public record GateRow(
            BigInteger qL, BigInteger qR, BigInteger qO, BigInteger qM, BigInteger qC,
            int wireA, int wireB, int wireC
    ) {}

    /**
     * A virtual wire computation instruction (snarkjs "addition").
     *
     * <p>Computes: {@code virtualWire = factorA * witness[wireA] + factorB * witness[wireB]}</p>
     *
     * <p>The prover uses these to extend the witness with virtual wire values
     * before evaluating the gate polynomials.</p>
     */
    public record Addition(int wireA, int wireB, BigInteger factorA, BigInteger factorB, int outputWire) {}

    public int domainSize() {
        // Pad to next power of 2
        int n = 1;
        while (n < numGates) n <<= 1;
        return n;
    }

    /**
     * Extend a base witness to include values for virtual intermediate wires.
     *
     * <p>Uses the {@link Addition} records (snarkjs-compatible) to compute virtual wire values.</p>
     */
    public BigInteger[] extendWitness(BigInteger[] baseWitness) {
        if (additions.isEmpty() && numWires <= baseWitness.length) return baseWitness;
        BigInteger p = fieldConfig.prime();
        BigInteger[] extended = new BigInteger[numWires];
        System.arraycopy(baseWitness, 0, extended, 0, Math.min(baseWitness.length, numWires));

        // Compute virtual wires from additions (in order)
        for (var add : additions) {
            BigInteger a = extended[add.wireA()];
            BigInteger b = extended[add.wireB()];
            if (a == null) a = BigInteger.ZERO;
            if (b == null) b = BigInteger.ZERO;
            extended[add.outputWire()] = add.factorA().multiply(a).add(add.factorB().multiply(b)).mod(p);
        }
        return extended;
    }
}
