package com.bloxbean.cardano.zeroj.circuit.halo2;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.List;

/**
 * A compiled Halo2 PLONKish circuit system.
 *
 * <p>Uses the same gate structure as PlonK (qL·a + qR·b + qO·c + qM·(a·b) + qC = 0)
 * but organized into Halo2's column/row model with advice columns and fixed selector columns.</p>
 *
 * <p>This is compatible with Halo2's basic arithmetic custom gate. Future versions will
 * support lookup arguments and more complex custom gates.</p>
 *
 * @param fieldConfig     field parameters (Pallas for IPA, BLS12-381 for KZG)
 * @param numRows         number of gate rows (padded to power of 2)
 * @param numPublicInputs number of public input signals
 * @param adviceColumns   wire assignments for each advice column (a, b, c) per row
 * @param selectorColumns selector values (qL, qR, qO, qM, qC) per row as field elements
 * @param permutation     copy constraints as column position cycles
 * @param k               circuit degree (log2 of domain size)
 * @param numWires        total number of wires including virtual intermediates
 */
public record Halo2CircuitSystem(
        FieldConfig fieldConfig,
        int numRows,
        int numPublicInputs,
        List<AdviceColumn> adviceColumns,
        List<SelectorColumn> selectorColumns,
        List<PermutationCycle> permutation,
        int k,
        int numWires
) {
    /** An advice column storing wire indices per row. */
    public record AdviceColumn(String name, int[] wireIndices) {}

    /** A fixed selector column storing field element values per row. */
    public record SelectorColumn(String name, BigInteger[] values) {}

    /** A permutation cycle: positions that must have equal values. */
    public record PermutationCycle(List<CellPosition> positions) {}

    /** A cell position in the circuit table. */
    public record CellPosition(int column, int row) {}

    /** Domain size = 2^k. */
    public int domainSize() { return 1 << k; }

    /**
     * Extend a base witness to include values for virtual intermediate wires
     * created during LinComb chaining.
     *
     * <p>Virtual wires (baseLen..numWires-1) are computed by evaluating gate rows in order.</p>
     */
    public BigInteger[] extendWitness(BigInteger[] baseWitness) {
        if (numWires <= baseWitness.length) return baseWitness;
        BigInteger p = fieldConfig.prime();
        BigInteger[] extended = new BigInteger[numWires];
        System.arraycopy(baseWitness, 0, extended, 0, baseWitness.length);
        // Virtual wires are null until computed
        // Compute virtual wire values from gate rows in order
        var colA = adviceColumns.get(0).wireIndices();
        var colB = adviceColumns.get(1).wireIndices();
        var colC = adviceColumns.get(2).wireIndices();
        var qL = selectorColumns.get(0).values();
        var qR = selectorColumns.get(1).values();
        var qO = selectorColumns.get(2).values();
        var qM = selectorColumns.get(3).values();
        var qC = selectorColumns.get(4).values();

        for (int i = 0; i < numRows; i++) {
            int wireC = colC[i];
            if (wireC >= baseWitness.length && extended[wireC] == null) {
                BigInteger a = extended[colA[i]];
                BigInteger b = extended[colB[i]];
                // qL*a + qR*b + qM*a*b + qC + qO*c = 0  →  c = -(qL*a + qR*b + qM*a*b + qC) / qO
                BigInteger sum = qL[i].multiply(a)
                        .add(qR[i].multiply(b))
                        .add(qM[i].multiply(a).multiply(b))
                        .add(qC[i])
                        .mod(p);
                BigInteger negQO = qO[i].negate().mod(p);
                BigInteger c = sum.multiply(negQO.modInverse(p)).mod(p);
                extended[wireC] = c;
            }
        }
        return extended;
    }

    /**
     * Serialize to JSON (intermediate format for Halo2 Rust FFM prover).
     */
    public String toJson(BigInteger[] witness) {
        var sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"version\": \"1.0\",\n");
        sb.append("  \"k\": ").append(k).append(",\n");
        sb.append("  \"numRows\": ").append(numRows).append(",\n");
        sb.append("  \"numPublicInputs\": ").append(numPublicInputs).append(",\n");
        sb.append("  \"field\": \"").append(fieldConfig.name()).append("\",\n");

        // Advice columns with witness values
        sb.append("  \"adviceColumns\": [\n");
        for (int c = 0; c < adviceColumns.size(); c++) {
            var col = adviceColumns.get(c);
            sb.append("    {\"name\": \"").append(col.name()).append("\", \"values\": [");
            for (int r = 0; r < numRows; r++) {
                if (r > 0) sb.append(", ");
                int wireIdx = col.wireIndices()[r];
                sb.append("\"").append(witness != null && wireIdx < witness.length && witness[wireIdx] != null
                        ? witness[wireIdx].toString() : "0").append("\"");
            }
            sb.append("]}");
            if (c < adviceColumns.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        // Fixed (selector) columns
        sb.append("  \"fixedColumns\": [\n");
        for (int c = 0; c < selectorColumns.size(); c++) {
            var col = selectorColumns.get(c);
            sb.append("    {\"name\": \"").append(col.name()).append("\", \"values\": [");
            for (int r = 0; r < numRows; r++) {
                if (r > 0) sb.append(", ");
                sb.append("\"").append(col.values()[r]).append("\"");
            }
            sb.append("]}");
            if (c < selectorColumns.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        // Permutation
        sb.append("  \"permutationCycles\": ").append(permutation.size()).append("\n");

        sb.append("}\n");
        return sb.toString();
    }
}
