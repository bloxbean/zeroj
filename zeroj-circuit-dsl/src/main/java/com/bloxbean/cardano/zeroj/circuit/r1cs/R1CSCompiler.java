package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.circuit.*;

import java.math.BigInteger;
import java.util.*;

/**
 * Compiles a {@link ConstraintGraph} into an {@link R1CSConstraintSystem}.
 *
 * <p>Key optimization: additions are free. When an Add gate feeds into a Mul gate,
 * the addition is absorbed into the linear combination (A, B, or C vector) rather
 * than creating a separate constraint.</p>
 *
 * <p>Memory (ADR-0034): constraints are emitted straight into packed CSR storage
 * ({@link R1CSFlat}), and the expression map holds only <em>live</em> derived expressions —
 * a pre-pass counts each wire's reads, and an expression is evicted on its last read. At 19M
 * constraints the old design retained every derived-expression map through the whole
 * compile+prove (the maps were aliased into the constraint list), ~7.4 GB of HashMap/boxing;
 * packed rows are ~12 B/term and the live map set is just the working frontier.</p>
 */
public final class R1CSCompiler {

    private R1CSCompiler() {}

    /**
     * Compile a constraint graph to R1CS.
     */
    public static R1CSConstraintSystem compile(ConstraintGraph graph, FieldConfig config) {
        BigInteger p = config.prime();

        // Pre-pass (ADR-0034 M2): count how many times each wire is READ as an expression —
        // exactly mirroring the getExpr call sites below. consumeExpr() decrements on each read
        // and evicts a derived expression after its last one, so exprMap holds only the live
        // frontier instead of every derived expression ever built.
        int[] reads = new int[graph.numWires()];
        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Add(var out, var left, var right) -> { reads[left.id()]++; reads[right.id()]++; }
                case Gate.LinComb(var out, var terms) -> { for (var t : terms) reads[t.variable().id()]++; }
                case Gate.Mul(var out, var left, var right) -> { reads[left.id()]++; reads[right.id()]++; }
                case Gate.AssertEq(var left, var right) -> { reads[left.id()]++; reads[right.id()]++; }
                default -> { }
            }
        }

        // Expression map: for each variable, its linear combination in terms of base variables.
        // Base variables: inputs, constants (wire 0), and multiplication outputs.
        // Derived variables: outputs of Add, LinComb, Neg gates.
        //
        // ADR-0034 M1: base variables are NOT stored — getExpr()/consumeExpr() default absent
        // wires to Map.of(id, ONE), which is exactly what a base entry would hold.
        Map<Integer, Map<Integer, BigInteger>> exprMap = new HashMap<>();

        // Constraints go straight into packed CSR form; the row maps are copied, not retained.
        R1CSFlat.Builder builder = R1CSFlat.builder();

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) -> {
                    // Constant is a linear combination: out = value * wire_0
                    exprMap.put(out.id(), Map.of(graph.oneWire().id(), value.mod(p)));
                }

                case Gate.Add(var out, var left, var right) -> {
                    // Free: merge linear combinations
                    var leftExpr = consumeExpr(exprMap, reads, left.id());
                    var rightExpr = consumeExpr(exprMap, reads, right.id());
                    exprMap.put(out.id(), addExprs(leftExpr, rightExpr, p));
                }

                case Gate.LinComb(var out, var terms) -> {
                    // Free: build linear combination
                    Map<Integer, BigInteger> combined = new HashMap<>();
                    for (var term : terms) {
                        var termExpr = consumeExpr(exprMap, reads, term.variable().id());
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
                    var a = consumeExpr(exprMap, reads, left.id());
                    var b = consumeExpr(exprMap, reads, right.id());
                    builder.add(a, b, Map.of(out.id(), BigInteger.ONE));
                    // Multiplication output is a new base variable (getExpr default)
                    exprMap.remove(out.id());
                }

                case Gate.AssertEq(var left, var right) -> {
                    // (left - right) * 1 = 0
                    var leftExpr = consumeExpr(exprMap, reads, left.id());
                    var rightExpr = consumeExpr(exprMap, reads, right.id());
                    var diff = subExprs(leftExpr, rightExpr, p);
                    if (!diff.isEmpty()) {
                        builder.add(diff,
                                Map.of(graph.oneWire().id(), BigInteger.ONE),
                                Map.of() /* = 0 */);
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

        R1CSFlat flat = builder.build();
        return new R1CSConstraintSystem(config, graph.numWires(),
                graph.publicInputs().size(), graph.secretInputs().size(), flat.asList(), flat);
    }

    /**
     * Read wire {@code wireId}'s expression and consume one of its pre-counted reads; a derived
     * expression is evicted from the map on its last read (the returned reference stays valid).
     * Absent wires are base variables: {@code Map.of(id, ONE)}.
     */
    private static Map<Integer, BigInteger> consumeExpr(Map<Integer, Map<Integer, BigInteger>> exprMap,
                                                        int[] reads, int wireId) {
        var expr = exprMap.get(wireId);
        if (--reads[wireId] <= 0 && expr != null) exprMap.remove(wireId);
        return expr != null ? expr : Map.of(wireId, BigInteger.ONE);
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
