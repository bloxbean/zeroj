package com.bloxbean.cardano.zeroj.circuit.plonk;

import com.bloxbean.cardano.zeroj.circuit.*;

import java.math.BigInteger;
import java.util.*;

/**
 * Compiles a {@link ConstraintGraph} into a {@link PlonKConstraintSystem}.
 *
 * <p>Each gate becomes one or more rows in the gate table:
 * {@code qL*a + qR*b + qO*c + qM*(a*b) + qC = 0}</p>
 *
 * <p>Also builds the permutation sigma (copy constraints) that enforces
 * the same variable has the same value across all gate rows where it appears.</p>
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
        int virtualWireOffset = 0; // offset for intermediate wires created during LinComb chaining

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Add(var out, var left, var right) -> {
                    // qL=1, qR=1, qO=-1: a + b - c = 0
                    rows.add(new PlonKConstraintSystem.GateRow(
                            ONE, ONE, negOne, ZERO, ZERO,
                            left.id(), right.id(), out.id()));
                }

                case Gate.Mul(var out, var left, var right) -> {
                    // qM=1, qO=-1: a*b - c = 0
                    rows.add(new PlonKConstraintSystem.GateRow(
                            ZERO, ZERO, negOne, ONE, ZERO,
                            left.id(), right.id(), out.id()));
                }

                case Gate.Const(var out, var value) -> {
                    // qO=-1, qC=value: -c + value = 0
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
                        // output = 0
                        rows.add(new PlonKConstraintSystem.GateRow(
                                ZERO, ZERO, negOne, ZERO, ZERO,
                                dummyWire, dummyWire, out.id()));
                    } else if (terms.size() == 1) {
                        // qL=coeff, qO=-1: coeff*a - c = 0
                        rows.add(new PlonKConstraintSystem.GateRow(
                                terms.getFirst().coefficient().mod(p), ZERO, negOne, ZERO, ZERO,
                                terms.getFirst().variable().id(), dummyWire, out.id()));
                    } else if (terms.size() == 2) {
                        // qL=c0, qR=c1, qO=-1: c0*a + c1*b - c = 0
                        var t0 = terms.get(0);
                        var t1 = terms.get(1);
                        rows.add(new PlonKConstraintSystem.GateRow(
                                t0.coefficient().mod(p), t1.coefficient().mod(p), negOne, ZERO, ZERO,
                                t0.variable().id(), t1.variable().id(), out.id()));
                    } else {
                        // Chain multi-term LinComb through intermediate addition gates.
                        // t0+t1 → inter0, inter0+t2 → inter1, ..., interN+tLast → out
                        var t0 = terms.get(0);
                        var t1 = terms.get(1);
                        int nextVirtualWire = graph.numWires() + virtualWireOffset;
                        int intermediateWire = nextVirtualWire;
                        virtualWireOffset++;

                        // First pair → intermediate
                        rows.add(new PlonKConstraintSystem.GateRow(
                                t0.coefficient().mod(p), t1.coefficient().mod(p), negOne, ZERO, ZERO,
                                t0.variable().id(), t1.variable().id(), intermediateWire));

                        // Remaining terms: accumulate running sum + next term
                        for (int i = 2; i < terms.size(); i++) {
                            var ti = terms.get(i);
                            boolean isLast = (i == terms.size() - 1);
                            int targetWire = isLast ? out.id() : (graph.numWires() + virtualWireOffset);
                            if (!isLast) virtualWireOffset++;

                            // running_sum * 1 + ti.coeff * ti.wire - target = 0
                            rows.add(new PlonKConstraintSystem.GateRow(
                                    ONE, ti.coefficient().mod(p), negOne, ZERO, ZERO,
                                    intermediateWire, ti.variable().id(), targetWire));
                            intermediateWire = targetWire;
                        }
                    }
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) -> {
                    // Decomposed into Add/Mul/AssertEq by CircuitAPIImpl, so shouldn't appear.
                    throw new UnsupportedOperationException(
                            "Select gate should be decomposed before PlonK compilation");
                }

                case Gate.BitDecompose(var outputs, var input, var nBits) -> {
                    // Hints don't create gates — they only guide witness calculation.
                }

                case Gate.Hint(var out, var type, var input) -> {
                    // Hints don't create gates — they only guide witness calculation.
                }
            }
        }

        int numGates = rows.size();

        // Build permutation sigma
        // Track where each wire appears: wireId → list of (row, column) positions
        Map<Integer, List<int[]>> wirePositions = new HashMap<>();
        for (int row = 0; row < numGates; row++) {
            var gateRow = rows.get(row);
            wirePositions.computeIfAbsent(gateRow.wireA(), k -> new ArrayList<>()).add(new int[]{row, 0});
            wirePositions.computeIfAbsent(gateRow.wireB(), k -> new ArrayList<>()).add(new int[]{row, 1});
            wirePositions.computeIfAbsent(gateRow.wireC(), k -> new ArrayList<>()).add(new int[]{row, 2});
        }

        // Initialize sigma as identity permutation
        int[] sigmaA = new int[numGates];
        int[] sigmaB = new int[numGates];
        int[] sigmaC = new int[numGates];
        for (int i = 0; i < numGates; i++) {
            sigmaA[i] = i;                    // column 0: positions 0..n-1
            sigmaB[i] = i + numGates;         // column 1: positions n..2n-1
            sigmaC[i] = i + 2 * numGates;     // column 2: positions 2n..3n-1
        }

        // For each wire that appears in multiple positions, create a cyclic permutation
        for (var positions : wirePositions.values()) {
            if (positions.size() <= 1) continue;

            // Create cycle: p0 → p1 → p2 → ... → pk → p0
            for (int i = 0; i < positions.size(); i++) {
                int[] from = positions.get(i);
                int[] to = positions.get((i + 1) % positions.size());

                int fromIdx = from[0] + from[1] * numGates; // flattened index
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
                graph.numWires() + virtualWireOffset, K1, K2);
    }
}
