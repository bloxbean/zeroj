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
        int dummyWire = graph.oneWire().id();

        // Build gate rows (same logic as PlonK compiler)
        List<GateRow> rows = new ArrayList<>();

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Add(var out, var left, var right) ->
                        rows.add(new GateRow(ONE, ONE, NEG_ONE, ZERO, ZERO,
                                left.id(), right.id(), out.id()));

                case Gate.Mul(var out, var left, var right) ->
                        rows.add(new GateRow(ZERO, ZERO, NEG_ONE, ONE, ZERO,
                                left.id(), right.id(), out.id()));

                case Gate.Const(var out, var value) ->
                        rows.add(new GateRow(ZERO, ZERO, NEG_ONE, ZERO, value.mod(p),
                                dummyWire, dummyWire, out.id()));

                case Gate.AssertEq(var left, var right) ->
                        rows.add(new GateRow(ONE, NEG_ONE, ZERO, ZERO, ZERO,
                                left.id(), right.id(), dummyWire));

                case Gate.LinComb(var out, var terms) -> {
                    if (terms.size() >= 2) {
                        rows.add(new GateRow(
                                terms.get(0).coefficient().mod(p),
                                terms.get(1).coefficient().mod(p),
                                NEG_ONE, ZERO, ZERO,
                                terms.get(0).variable().id(),
                                terms.get(1).variable().id(),
                                out.id()));
                    } else if (terms.size() == 1) {
                        rows.add(new GateRow(
                                terms.getFirst().coefficient().mod(p),
                                ZERO, NEG_ONE, ZERO, ZERO,
                                terms.getFirst().variable().id(), dummyWire, out.id()));
                    }
                }

                case Gate.Select(var out, _, _, _) ->
                        rows.add(new GateRow(ZERO, ZERO, NEG_ONE, ZERO, ZERO,
                                dummyWire, dummyWire, out.id()));

                // Hints and BitDecompose don't create gates
                case Gate.Hint(_, _, _) -> {}
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

        // Build fixed selector columns (store selector values as encoded integers)
        // For serialization, we store the raw BigInteger values
        int[] fqL = new int[numRows], fqR = new int[numRows], fqO = new int[numRows];
        int[] fqM = new int[numRows], fqC = new int[numRows];
        for (int i = 0; i < numRows; i++) {
            fqL[i] = rows.get(i).qL.intValue();
            fqR[i] = rows.get(i).qR.intValue();
            fqO[i] = rows.get(i).qO.intValue();
            fqM[i] = rows.get(i).qM.intValue();
            fqC[i] = rows.get(i).qC.intValue();
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
                        new Halo2CircuitSystem.Column("a", colA),
                        new Halo2CircuitSystem.Column("b", colB),
                        new Halo2CircuitSystem.Column("c", colC)),
                List.of(
                        new Halo2CircuitSystem.Column("qL", fqL),
                        new Halo2CircuitSystem.Column("qR", fqR),
                        new Halo2CircuitSystem.Column("qO", fqO),
                        new Halo2CircuitSystem.Column("qM", fqM),
                        new Halo2CircuitSystem.Column("qC", fqC)),
                cycles, k);
    }

    /** Internal gate row representation. */
    private record GateRow(BigInteger qL, BigInteger qR, BigInteger qO, BigInteger qM, BigInteger qC,
                           int wireA, int wireB, int wireC) {}
}
