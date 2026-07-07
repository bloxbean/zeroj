package com.bloxbean.cardano.zeroj.circuit.halo2;

import com.bloxbean.cardano.zeroj.circuit.*;

import java.math.BigInteger;
import java.util.*;

/**
 * Compiles a {@link ConstraintGraph} into a {@link Halo2CircuitSystem}.
 *
 * <p>Translates the proof-system-agnostic constraint graph into Halo2's PLONKish model:
 * <ul>
 *   <li>3 advice columns (a, b, c) — same as PlonK wire columns</li>
 *   <li>5 fixed selector columns (qL, qR, qO, qM, qC)</li>
 *   <li>Copy constraints as permutation cycles</li>
 *   <li>Single "default" region containing all gates (MVP — regions are optional)</li>
 * </ul>
 *
 * <p>The basic arithmetic custom gate enforces:
 * {@code qL·a + qR·b + qO·c + qM·(a·b) + qC = 0} at each enabled row.</p>
 *
 * <p>This is compatible with both Halo2 IPA (Pallas/Vesta) and Halo2 KZG (BLS12-381).</p>
 */
public final class Halo2Compiler {

    private Halo2Compiler() {}

    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger NEG_ONE = BigInteger.ONE.negate();
    private static final BigInteger ZERO = BigInteger.ZERO;

    /**
     * Compile a constraint graph to a Halo2 PLONKish circuit system.
     */
    public static Halo2CircuitSystem compile(ConstraintGraph graph, FieldConfig config) {
        BigInteger p = config.prime();
        // Normalize constants to field: -1 mod p = p-1
        BigInteger negOne = NEG_ONE.mod(p);
        int dummyWire = graph.oneWire().id();

        // Build gate rows
        List<GateRow> rows = new ArrayList<>();
        int virtualWireOffset = 0; // offset for intermediate wires created during LinComb chaining

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Add(var out, var left, var right) ->
                        rows.add(new GateRow(ONE, ONE, negOne, ZERO, ZERO,
                                left.id(), right.id(), out.id()));

                case Gate.Mul(var out, var left, var right) ->
                        rows.add(new GateRow(ZERO, ZERO, negOne, ONE, ZERO,
                                left.id(), right.id(), out.id()));

                case Gate.Const(var out, var value) ->
                        rows.add(new GateRow(ZERO, ZERO, negOne, ZERO, value.mod(p),
                                dummyWire, dummyWire, out.id()));

                case Gate.AssertEq(var left, var right) ->
                        rows.add(new GateRow(ONE, negOne, ZERO, ZERO, ZERO,
                                left.id(), right.id(), dummyWire));

                case Gate.LinComb(var out, var terms) -> {
                    if (terms.isEmpty()) {
                        // output = 0
                        rows.add(new GateRow(ZERO, ZERO, negOne, ZERO, ZERO,
                                dummyWire, dummyWire, out.id()));
                    } else if (terms.size() == 1) {
                        rows.add(new GateRow(
                                terms.getFirst().coefficient().mod(p), ZERO, negOne, ZERO, ZERO,
                                terms.getFirst().variable().id(), dummyWire, out.id()));
                    } else if (terms.size() == 2) {
                        var t0 = terms.get(0);
                        var t1 = terms.get(1);
                        rows.add(new GateRow(
                                t0.coefficient().mod(p), t1.coefficient().mod(p), negOne, ZERO, ZERO,
                                t0.variable().id(), t1.variable().id(), out.id()));
                    } else {
                        // Chain multi-term LinComb through intermediate addition gates.
                        // t0+t1 → inter0, inter0+t2 → inter1, ..., interN+tLast → out
                        var t0 = terms.get(0);
                        var t1 = terms.get(1);
                        int intermediateWire = graph.numWires() + virtualWireOffset;
                        virtualWireOffset++;

                        // First pair → intermediate
                        rows.add(new GateRow(
                                t0.coefficient().mod(p), t1.coefficient().mod(p), negOne, ZERO, ZERO,
                                t0.variable().id(), t1.variable().id(), intermediateWire));

                        // Remaining terms: accumulate running sum + next term
                        for (int i = 2; i < terms.size(); i++) {
                            var ti = terms.get(i);
                            boolean isLast = (i == terms.size() - 1);
                            int targetWire = isLast ? out.id() : (graph.numWires() + virtualWireOffset);
                            if (!isLast) virtualWireOffset++;

                            // running_sum * 1 + ti.coeff * ti.wire - target = 0
                            rows.add(new GateRow(
                                    ONE, ti.coefficient().mod(p), negOne, ZERO, ZERO,
                                    intermediateWire, ti.variable().id(), targetWire));
                            intermediateWire = targetWire;
                        }
                    }
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) -> {
                    // Decomposed into Add/Mul/AssertEq by CircuitAPIImpl, so shouldn't appear.
                    throw new UnsupportedOperationException(
                            "Select gate should be decomposed before Halo2 compilation");
                }

                // Hints and BitDecompose don't create gates
                case Gate.Hint(_, _, _) -> {}
                case Gate.HintN(_, _, _, _) -> {}
                case Gate.BitDecompose(_, _, _) -> {}
            }
        }

        int numRows = rows.size();

        // Compute k (log2 of domain size)
        int domainSize = 1;
        int k = 0;
        while (domainSize < numRows) {
            domainSize <<= 1;
            k++;
        }
        if (k == 0) k = 1; // minimum k=1

        // Build advice columns (wire assignments per row)
        int[] colA = new int[numRows];
        int[] colB = new int[numRows];
        int[] colC = new int[numRows];
        for (int i = 0; i < numRows; i++) {
            colA[i] = rows.get(i).wireA;
            colB[i] = rows.get(i).wireB;
            colC[i] = rows.get(i).wireC;
        }

        // Build fixed selector columns (BigInteger values — no truncation)
        BigInteger[] fqL = new BigInteger[numRows], fqR = new BigInteger[numRows];
        BigInteger[] fqO = new BigInteger[numRows], fqM = new BigInteger[numRows];
        BigInteger[] fqC = new BigInteger[numRows];
        for (int i = 0; i < numRows; i++) {
            fqL[i] = rows.get(i).qL;
            fqR[i] = rows.get(i).qR;
            fqO[i] = rows.get(i).qO;
            fqM[i] = rows.get(i).qM;
            fqC[i] = rows.get(i).qC;
        }

        // Build permutation cycles
        // Track where each wire appears: wireId → list of (column, row)
        Map<Integer, List<Halo2CircuitSystem.CellPosition>> wirePositions = new HashMap<>();
        for (int row = 0; row < numRows; row++) {
            wirePositions.computeIfAbsent(colA[row], w -> new ArrayList<>())
                    .add(new Halo2CircuitSystem.CellPosition(0, row));
            wirePositions.computeIfAbsent(colB[row], w -> new ArrayList<>())
                    .add(new Halo2CircuitSystem.CellPosition(1, row));
            wirePositions.computeIfAbsent(colC[row], w -> new ArrayList<>())
                    .add(new Halo2CircuitSystem.CellPosition(2, row));
        }

        List<Halo2CircuitSystem.PermutationCycle> cycles = new ArrayList<>();
        for (var positions : wirePositions.values()) {
            if (positions.size() > 1) {
                cycles.add(new Halo2CircuitSystem.PermutationCycle(positions));
            }
        }

        return new Halo2CircuitSystem(
                config, numRows, graph.publicInputs().size(),
                List.of(
                        new Halo2CircuitSystem.AdviceColumn("a", colA),
                        new Halo2CircuitSystem.AdviceColumn("b", colB),
                        new Halo2CircuitSystem.AdviceColumn("c", colC)),
                List.of(
                        new Halo2CircuitSystem.SelectorColumn("qL", fqL),
                        new Halo2CircuitSystem.SelectorColumn("qR", fqR),
                        new Halo2CircuitSystem.SelectorColumn("qO", fqO),
                        new Halo2CircuitSystem.SelectorColumn("qM", fqM),
                        new Halo2CircuitSystem.SelectorColumn("qC", fqC)),
                cycles, k, graph.numWires() + virtualWireOffset);
    }

    /** Internal gate row representation. */
    private record GateRow(BigInteger qL, BigInteger qR, BigInteger qO, BigInteger qM, BigInteger qC,
                           int wireA, int wireB, int wireC) {}
}
