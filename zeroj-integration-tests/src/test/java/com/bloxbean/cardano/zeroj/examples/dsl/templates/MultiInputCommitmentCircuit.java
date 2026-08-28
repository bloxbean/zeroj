package com.bloxbean.cardano.zeroj.examples.dsl.templates;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitSpec;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.lib.PoseidonN;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

/**
 * Parameterized N-input commitment circuit — hash N secret values into one public digest.
 *
 * <p>Proves knowledge of N secret inputs whose sequential BLS12-381 Poseidon hash produces a
 * known public commitment. Useful for committing to structured data (e.g., a record
 * with multiple fields) without revealing any field.</p>
 *
 * <pre>{@code
 * // Circom equivalent:
 * template MultiCommit(n) {
 *     signal input values[n];
 *     signal output commitment;
 *     var acc = values[0];
 *     for (var i = 1; i < n; i++) {
 *         acc = PoseidonBLS12_381(acc, values[i]);
 *     }
 *     commitment <== acc;
 * }
 * }</pre>
 *
 * <p>Java advantage: the constructor can take <em>any</em> type of parameter —
 * not just integers. You could parameterize by field names, validation rules, etc.</p>
 *
 * @param numInputs number of secret values to commit (>= 2)
 * @param fieldNames optional descriptive names for each input (for readability)
 */
public class MultiInputCommitmentCircuit implements CircuitSpec {

    private final int numInputs;
    private final String[] fieldNames;

    public MultiInputCommitmentCircuit(int numInputs) {
        this(numInputs, defaultNames(numInputs));
    }

    public MultiInputCommitmentCircuit(int numInputs, String... fieldNames) {
        if (numInputs < 2) throw new IllegalArgumentException("numInputs must be >= 2");
        if (fieldNames.length != numInputs)
            throw new IllegalArgumentException("fieldNames.length must match numInputs");
        this.numInputs = numInputs;
        this.fieldNames = fieldNames;
    }

    @Override
    public void define(SignalBuilder c) {
        Signal[] inputs = new Signal[numInputs];
        for (int i = 0; i < numInputs; i++) {
            inputs[i] = c.privateInput(fieldNames[i]);
        }
        Signal commitment = c.publicOutput("commitment");

        Signal acc = PoseidonN.hash(c, PoseidonParamsBLS12_381T3.INSTANCE, inputs);

        c.assertEqual(acc, commitment);
    }

    public static CircuitBuilder build(int numInputs, String... fieldNames) {
        if (fieldNames.length == 0) fieldNames = defaultNames(numInputs);

        var builder = CircuitBuilder.create("multi-commit-" + numInputs)
                .publicVar("commitment");
        for (String name : fieldNames) {
            builder = builder.secretVar(name);
        }
        return builder.defineSignals(new MultiInputCommitmentCircuit(numInputs, fieldNames));
    }

    private static String[] defaultNames(int n) {
        String[] names = new String[n];
        for (int i = 0; i < n; i++) names[i] = "value_" + i;
        return names;
    }
}
