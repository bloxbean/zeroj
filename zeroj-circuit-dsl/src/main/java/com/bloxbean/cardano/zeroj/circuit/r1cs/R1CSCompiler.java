package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.circuit.*;

import java.math.BigInteger;
import java.util.*;

/**
 * Compiles a {@link ConstraintGraph} into an {@link R1CSConstraintSystem}.
 *
 * <p>Key optimization: additions are free. When an Add gate feeds into a Mul gate,
 * the addition is absorbed into the linear combination (A, B, or C vector) rather
 * than creating a separate constraint.</p>
 */
public final class R1CSCompiler {

    private R1CSCompiler() {}

    /**
     * Compile a constraint graph to R1CS.
     */
    public static R1CSConstraintSystem compile(ConstraintGraph graph, FieldConfig config) {
        BigInteger p = config.prime();

        // Build expression map: for each variable, its linear combination in terms of base variables.
        // Base variables: inputs, constants (wire 0), and multiplication outputs.
        // Derived variables: outputs of Add, LinComb, Neg gates.
        //
        // ADR-0034 M1: base variables are NOT stored — getExpr() defaults absent wires to
        // Map.of(id, ONE), which is exactly what a base entry would hold. At 43.7M wires the
        // ~19M base entries (node + boxed key + Map1 each) were ~1.5-2 GB of the compile peak.
        // Only derived expressions (Const/Add/LinComb outputs) live in the map.
        //
        // Pre-size both containers from a cheap gate-count pass: at 19M constraints the
        // constraints ArrayList otherwise re-copies a hundreds-of-MB humongous Object[] on every
        // grow (old + new arrays live simultaneously — an OOM trigger near the heap cap), and the
        // exprMap table (tens of millions of slots) re-hashes the same way.
        int constraintCount = 0, derivedCount = 0;
        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Mul g -> constraintCount++;
                case Gate.AssertEq g -> constraintCount++; // upper bound: empty diffs emit nothing
                case Gate.Add g -> derivedCount++;
                case Gate.LinComb g -> derivedCount++;
                case Gate.Const g -> derivedCount++;
                default -> { }
            }
        }
        Map<Integer, Map<Integer, BigInteger>> exprMap = HashMap.newHashMap(derivedCount + 8);

        List<R1CSConstraint> constraints = new ArrayList<>(constraintCount);

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) -> {
                    // Constant is a linear combination: out = value * wire_0
                    exprMap.put(out.id(), Map.of(graph.oneWire().id(), value.mod(p)));
                }

                case Gate.Add(var out, var left, var right) -> {
                    // Free: merge linear combinations
                    var leftExpr = getExpr(exprMap, left.id());
                    var rightExpr = getExpr(exprMap, right.id());
                    exprMap.put(out.id(), addExprs(leftExpr, rightExpr, p));
                }

                case Gate.LinComb(var out, var terms) -> {
                    // Free: build linear combination
                    Map<Integer, BigInteger> combined = new HashMap<>();
                    for (var term : terms) {
                        var termExpr = getExpr(exprMap, term.variable().id());
                        for (var entry : termExpr.entrySet()) {
                            combined.merge(entry.getKey(),
                                    entry.getValue().multiply(term.coefficient()).mod(p),
                                    (a, b) -> a.add(b).mod(p));
                        }
                    }
                    exprMap.put(out.id(), combined);
                }

                case Gate.Mul(var out, var left, var right) -> {
                    // Creates one R1CS constraint: A * B = C
                    var a = getExpr(exprMap, left.id());
                    var b = getExpr(exprMap, right.id());
                    var c = Map.of(out.id(), BigInteger.ONE);
                    constraints.add(new R1CSConstraint(a, b, c));
                    // Multiplication output is a new base variable (getExpr default)
                    exprMap.remove(out.id());
                }

                case Gate.AssertEq(var left, var right) -> {
                    // (left - right) * 1 = 0
                    var leftExpr = getExpr(exprMap, left.id());
                    var rightExpr = getExpr(exprMap, right.id());
                    var diff = subExprs(leftExpr, rightExpr, p);
                    if (!diff.isEmpty()) {
                        constraints.add(new R1CSConstraint(
                                diff,
                                Map.of(graph.oneWire().id(), BigInteger.ONE),
                                Map.of() // = 0
                        ));
                    }
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) -> {
                    // Handled by the expanded gates (assertBoolean + mul + add)
                    // The Select gate itself is not emitted by CircuitAPIImpl —
                    // it's decomposed into Add/Mul/AssertEq gates.
                    // If we encounter it, treat output as base variable (getExpr default).
                    exprMap.remove(out.id());
                }

                case Gate.BitDecompose(var outputs, var input, var nBits) -> {
                    // Hints don't create constraints. Each bit output is a base variable
                    // (getExpr default).
                    for (var o : outputs) exprMap.remove(o.id());
                }

                case Gate.Hint(var out, var type, var input) -> {
                    // Hints don't create constraints — they guide witness calculation.
                    // The hint output is a base variable (getExpr default).
                    exprMap.remove(out.id());
                }

                case Gate.HintN(var outputs, var kind, var inputs, var params) -> {
                    // Hints don't create constraints. Each output is a base variable (getExpr
                    // default); the caller adds the constraints that pin these values down
                    // (soundness lives there).
                    for (var o : outputs) exprMap.remove(o.id());
                }
            }
        }

        return new R1CSConstraintSystem(config, graph.numWires(),
                graph.publicInputs().size(), graph.secretInputs().size(), constraints);
    }

    private static Map<Integer, BigInteger> getExpr(Map<Integer, Map<Integer, BigInteger>> exprMap, int wireId) {
        var expr = exprMap.get(wireId);
        if (expr != null) return expr;
        // Unknown wire — treat as base variable
        return Map.of(wireId, BigInteger.ONE);
    }

    private static Map<Integer, BigInteger> addExprs(Map<Integer, BigInteger> a, Map<Integer, BigInteger> b,
                                                      BigInteger p) {
        var result = new HashMap<>(a);
        for (var entry : b.entrySet()) {
            result.merge(entry.getKey(), entry.getValue(), (x, y) -> x.add(y).mod(p));
        }
        // Remove zero entries
        result.values().removeIf(v -> v.signum() == 0);
        return result;
    }

    private static Map<Integer, BigInteger> subExprs(Map<Integer, BigInteger> a, Map<Integer, BigInteger> b,
                                                      BigInteger p) {
        var result = new HashMap<>(a);
        for (var entry : b.entrySet()) {
            result.merge(entry.getKey(), entry.getValue().negate().mod(p), (x, y) -> x.add(y).mod(p));
        }
        result.values().removeIf(v -> v.signum() == 0);
        return result;
    }
}
