package com.bloxbean.cardano.zeroj.circuit.plonk;

import com.bloxbean.cardano.zeroj.circuit.*;

import java.math.BigInteger;
import java.util.*;

/**
 * Compiles a {@link ConstraintGraph} into a {@link PlonKConstraintSystem}.
 *
 * <p>Follows the snarkjs PlonK convention for compatibility with snarkjs .zkey files,
 * circom circuits, and the existing PlonkBN254Verifier.</p>
 *
 * <h3>snarkjs alignment</h3>
 * <ul>
 *   <li>Public input rows are emitted first (one per public input, qL=1)</li>
 *   <li>Virtual wire reductions use snarkjs sign convention: qL=-coeff, qR=-coeff, qO=+1</li>
 *   <li>Virtual wire computations are tracked as separate {@link PlonKConstraintSystem.Addition} records</li>
 * </ul>
 *
 * <p>Each gate becomes one or more rows in the gate table:
 * {@code qL*a + qR*b + qO*c + qM*(a*b) + qC = 0}</p>
 */
public final class PlonKCompiler {

    private PlonKCompiler() {}

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger NEG_ONE = BigInteger.ONE.negate();
    private static final BigInteger ZERO = BigInteger.ZERO;

    /** Coset shift factors (matching snarkjs convention). */
    private static final BigInteger K1 = BigInteger.TWO;
    private static final BigInteger K2 = BigInteger.valueOf(3);

    /**
     * Compile a constraint graph to PlonK constraint system.
     */
    public static PlonKConstraintSystem compile(ConstraintGraph graph, FieldConfig config) {
        BigInteger p = config.prime();
        // Normalize constants to field: -1 mod p = p-1
        BigInteger negOne = NEG_ONE.mod(p);

        // Dummy wire for unused positions (wire 0 = constant 1)
        int dummyWire = graph.oneWire().id();

        List<PlonKConstraintSystem.GateRow> rows = new ArrayList<>();
        List<PlonKConstraintSystem.Addition> additions = new ArrayList<>();
        int virtualWireOffset = 0;

        // === snarkjs alignment: Public input rows come FIRST ===
        // One row per public input: qL=1, everything else=0, wireA = public input wire
        // These rows are anchors for the PI(X) Lagrange polynomial injection
        for (var pubVar : graph.publicInputs()) {
            rows.add(new PlonKConstraintSystem.GateRow(
                    ONE, ZERO, ZERO, ZERO, ZERO,
                    pubVar.id(), dummyWire, dummyWire));
        }

        // === Process circuit gates ===
        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Add(var out, var left, var right) -> {
                    // snarkjs convention: -1*a + -1*b + 1*c = 0 → c = a + b
                    rows.add(new PlonKConstraintSystem.GateRow(
                            negOne, negOne, ONE, ZERO, ZERO,
                            left.id(), right.id(), out.id()));
                }

                case Gate.Mul(var out, var left, var right) -> {
                    // qM=1, qO=-1: a*b - c = 0
                    // snarkjs convention for pure multiplication: qM=1, qO=-1
                    rows.add(new PlonKConstraintSystem.GateRow(
                            ZERO, ZERO, negOne, ONE, ZERO,
                            left.id(), right.id(), out.id()));
                }

                case Gate.Const(var out, var value) -> {
                    // snarkjs convention: qO=1, qC=-value: c - value = 0 → c = value
                    // Actually: -(-value) + 1*c = 0 → qO=1, qC=value.negate()
                    // Or equivalently: qO=-1, qC=value (our original) which is also valid
                    // Keep as: qO=negOne, qC=value (same constraint, just expressed as -c + value = 0)
                    rows.add(new PlonKConstraintSystem.GateRow(
                            ZERO, ZERO, negOne, ZERO, value.mod(p),
                            dummyWire, dummyWire, out.id()));
                }

                case Gate.AssertEq(var left, var right) -> {
                    // qL=1, qR=-1: a - b = 0
                    rows.add(new PlonKConstraintSystem.GateRow(
                            ONE, negOne, ZERO, ZERO, ZERO,
                            left.id(), right.id(), dummyWire));
                }

                case Gate.LinComb(var out, var terms) -> {
                    if (terms.isEmpty()) {
                        // output = 0: qO=1, qC=0 → c = 0
                        rows.add(new PlonKConstraintSystem.GateRow(
                                ZERO, ZERO, ONE, ZERO, ZERO,
                                dummyWire, dummyWire, out.id()));
                    } else if (terms.size() == 1) {
                        // snarkjs convention: -coeff*a + 1*c = 0 → c = coeff*a
                        var t = terms.getFirst();
                        rows.add(new PlonKConstraintSystem.GateRow(
                                t.coefficient().negate().mod(p), ZERO, ONE, ZERO, ZERO,
                                t.variable().id(), dummyWire, out.id()));
                    } else if (terms.size() == 2) {
                        // snarkjs convention: -c0*a + -c1*b + 1*c = 0 → c = c0*a + c1*b
                        var t0 = terms.get(0);
                        var t1 = terms.get(1);
                        rows.add(new PlonKConstraintSystem.GateRow(
                                t0.coefficient().negate().mod(p),
                                t1.coefficient().negate().mod(p),
                                ONE, ZERO, ZERO,
                                t0.variable().id(), t1.variable().id(), out.id()));
                    } else {
                        // Chain multi-term LinComb through intermediate addition gates.
                        // snarkjs convention: -coeff1*a + -coeff2*b + 1*c = 0 per reduction step
                        // Also record Addition(wireA, wireB, coeff1, coeff2, outputWire)
                        var t0 = terms.get(0);
                        var t1 = terms.get(1);
                        int intermediateWire = graph.numWires() + virtualWireOffset;
                        virtualWireOffset++;

                        // First pair → intermediate
                        rows.add(new PlonKConstraintSystem.GateRow(
                                t0.coefficient().negate().mod(p),
                                t1.coefficient().negate().mod(p),
                                ONE, ZERO, ZERO,
                                t0.variable().id(), t1.variable().id(), intermediateWire));
                        additions.add(new PlonKConstraintSystem.Addition(
                                t0.variable().id(), t1.variable().id(),
                                t0.coefficient().mod(p), t1.coefficient().mod(p),
                                intermediateWire));

                        // Remaining terms: -1*running_sum + -coeff_i*term_i + 1*target = 0
                        for (int i = 2; i < terms.size(); i++) {
                            var ti = terms.get(i);
                            boolean isLast = (i == terms.size() - 1);
                            int targetWire = isLast ? out.id() : (graph.numWires() + virtualWireOffset);
                            if (!isLast) virtualWireOffset++;

                            rows.add(new PlonKConstraintSystem.GateRow(
                                    negOne, ti.coefficient().negate().mod(p),
                                    ONE, ZERO, ZERO,
                                    intermediateWire, ti.variable().id(), targetWire));
                            additions.add(new PlonKConstraintSystem.Addition(
                                    intermediateWire, ti.variable().id(),
                                    ONE, ti.coefficient().mod(p),
                                    targetWire));
                            intermediateWire = targetWire;
                        }
                    }
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) -> {
                    throw new UnsupportedOperationException(
                            "Select gate should be decomposed before PlonK compilation");
                }

                case Gate.BitDecompose(var outputs, var input, var nBits) -> {
                    // Hints don't create gates
                }

                case Gate.Hint(var out, var type, var input) -> {
                    // Hints don't create gates
                }
            }
        }

        int numGates = rows.size();

        // Build permutation sigma
        Map<Integer, List<int[]>> wirePositions = new HashMap<>();
        for (int row = 0; row < numGates; row++) {
            var gateRow = rows.get(row);
            wirePositions.computeIfAbsent(gateRow.wireA(), k -> new ArrayList<>()).add(new int[]{row, 0});
            wirePositions.computeIfAbsent(gateRow.wireB(), k -> new ArrayList<>()).add(new int[]{row, 1});
            wirePositions.computeIfAbsent(gateRow.wireC(), k -> new ArrayList<>()).add(new int[]{row, 2});
        }

        int[] sigmaA = new int[numGates];
        int[] sigmaB = new int[numGates];
        int[] sigmaC = new int[numGates];
        for (int i = 0; i < numGates; i++) {
            sigmaA[i] = i;
            sigmaB[i] = i + numGates;
            sigmaC[i] = i + 2 * numGates;
        }

        for (var positions : wirePositions.values()) {
            if (positions.size() <= 1) continue;
            for (int i = 0; i < positions.size(); i++) {
                int[] from = positions.get(i);
                int[] to = positions.get((i + 1) % positions.size());
                int toIdx = to[0] + to[1] * numGates;
                switch (from[1]) {
                    case 0 -> sigmaA[from[0]] = toIdx;
                    case 1 -> sigmaB[from[0]] = toIdx;
                    case 2 -> sigmaC[from[0]] = toIdx;
                }
            }
        }

        return new PlonKConstraintSystem(config, numGates,
                graph.publicInputs().size(), rows, sigmaA, sigmaB, sigmaC,
                graph.numWires() + virtualWireOffset, K1, K2, additions);
    }
}
