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
 * @param adviceAssignments wire values for each advice column (a, b, c) per row
 * @param fixedColumns    selector values (qL, qR, qO, qM, qC) per row
 * @param permutation     copy constraints as column position cycles
 * @param k               circuit degree (log2 of domain size)
 */
public record Halo2CircuitSystem(
        FieldConfig fieldConfig,
        int numRows,
        int numPublicInputs,
        List<Column> adviceColumns,
        List<Column> fixedColumns,
        List<PermutationCycle> permutation,
        int k
) {
    /** A column of values (advice or fixed). */
    public record Column(String name, int[] wireIndices) {}

    /** A permutation cycle: positions that must have equal values. */
    public record PermutationCycle(List<CellPosition> positions) {}

    /** A cell position in the circuit table. */
    public record CellPosition(int column, int row) {}

    /** Domain size = 2^k. */
    public int domainSize() { return 1 << k; }

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
        for (int c = 0; c < fixedColumns.size(); c++) {
            var col = fixedColumns.get(c);
            sb.append("    {\"name\": \"").append(col.name()).append("\", \"values\": [");
            // Fixed columns store selector values directly (encoded as wire indices pointing to constants)
            // For serialization, we output the values from the gate rows
            for (int r = 0; r < numRows; r++) {
                if (r > 0) sb.append(", ");
                int wireIdx = col.wireIndices()[r];
                sb.append("\"").append(wireIdx).append("\"");
            }
            sb.append("]}");
            if (c < fixedColumns.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("  ],\n");

        // Permutation
        sb.append("  \"permutationCycles\": ").append(permutation.size()).append("\n");

        sb.append("}\n");
        return sb.toString();
    }
}
