package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.CircuitDefinition;
import com.bloxbean.cardano.zeroj.circuit.ConstraintGraph;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0038 Decision 3 / phase P3: linear-expression inlining is fan-out aware.
 *
 * <p>The gate is deliberately two-sided. Adversarial shapes must stay inside the compiler's
 * fixed CSR/live/work limits and be repaired without wholesale materialise-all fallback. Stable
 * production shapes remain pinned to the incumbent all-inline rows/NNZ elsewhere in the suite.
 */
class LinearInliningPolicyTest {

    private static final FieldConfig FIELD = FieldConfig.BLS12_381;
    private static final BigInteger P = FIELD.prime();

    // ------------------------------------------------------------------
    //  The reported reproducer, in both variants
    // ------------------------------------------------------------------

    /**
     * The shape ADR-0038 finding 3 reports: one wide expression read by many multiplications.
     * Under all-inline the expression is copied into every reader, so nonzeros grow as T×F.
     */
    private static CircuitDefinition constantMulFanOut(int terms, int fanOut) {
        return api -> {
            // A `terms`-term linear expression...
            Variable wide = api.constant(0);
            for (int i = 0; i < terms; i++) {
                wide = api.add(wide, api.mul(api.var("x" + i), api.constant(i + 2)));
            }
            // ...scaled by a constant, then read from `fanOut` distinct multiplications.
            Variable scaled = api.mul(wide, api.constant(7));
            Variable acc = api.constant(0);
            for (int i = 0; i < fanOut; i++) {
                acc = api.add(acc, api.mul(scaled, api.var("y" + i)));
            }
            api.assertEqual(acc, acc);
        };
    }

    /** The sibling shape with no constant multiplication anywhere — pure Add/LinComb. */
    private static CircuitDefinition pureAddFanOut(int terms, int fanOut) {
        return api -> {
            Variable wide = api.constant(0);
            for (int i = 0; i < terms; i++) {
                wide = api.add(wide, api.var("x" + i));
            }
            Variable acc = api.constant(0);
            for (int i = 0; i < fanOut; i++) {
                acc = api.add(acc, api.mul(wide, api.var("y" + i)));
            }
            api.assertEqual(acc, acc);
        };
    }

    private static ConstraintGraph graphOf(CircuitDefinition def, int terms, int fanOut) {
        var builder = CircuitBuilder.create("fanout");
        for (int i = 0; i < terms; i++) builder = builder.secretVar("x" + i);
        for (int i = 0; i < fanOut; i++) builder = builder.secretVar("y" + i);
        return builder.define(def).constraintGraph();
    }

    @Test
    void constantMulFanOut_selectedPolicyStaysWithinMaterialiseAllBaseline() {
        assertWithinBaseline(graphOf(constantMulFanOut(500, 500), 500, 500));
    }

    @Test
    void pureAddLinCombFanOut_selectedPolicyStaysWithinMaterialiseAllBaseline() {
        assertWithinBaseline(graphOf(pureAddFanOut(500, 500), 500, 500));
    }

    /**
     * A wide expression copied through a binary tree defeats every immediate-fan-out ratio:
     * each node is read exactly twice, yet after nine levels the expression reaches 512 terminal
     * multiplication rows. The local heuristic is intentionally allowed to miss this shape;
     * the public compiler's live-frontier/work pressure must catch it during the same emission
     * pass and collapse the wide frontier.
     */
    @Test
    void distributedBinaryFanOut_publicCompilerRepairsWithinResourceLimits() {
        ConstraintGraph graph = distributedBinaryFanOutGraph(500, 9);
        var baseline = compile(graph, LinearInliningPolicy.materialiseAll(graph, P));
        var candidate = compile(graph, LinearInliningPolicy.select(graph, P));
        var compiled = R1CSCompiler.compileWithDiagnostics(graph, FIELD);
        var enforced = compiled.system();
        var limits = R1CSCompiler.resourceLimits(graph);

        // Explicitly pin the accepted row/NNZ tradeoff. Pressure lowers the dominant
        // row/domain metric (1,011 -> 529 rows; padded domain 2,048 -> 1,024) while retaining
        // 2.85x the materialise-all sparse terms. The public contract intentionally does not
        // claim to dominate materialise-all on both metrics.
        assertEquals(1_011, baseline.constraints().size());
        assertEquals(3_532, nnz(baseline));
        assertEquals(529, enforced.constraints().size());
        assertEquals(10_070, nnz(enforced));
        assertTrue(compiled.diagnostics().pressureModeEntered(),
                "distributed fixture must surface its pressure-triggered shape change");
        assertEquals(529, compiled.diagnostics().rows());
        assertEquals(10_070, compiled.diagnostics().totalCsrTerms());
        assertTrue(compiled.diagnostics().cumulativeExpressionWorkTerms() > 0);

        assertTrue(nnz(candidate) > nnz(baseline) * 10,
                "fixture must remain a load-bearing counterexample to the local heuristic");
        assertTrue(enforced.constraints().size() <= baseline.constraints().size(),
                "online repair bought more rows than aggressive materialisation");
        assertTrue(nnz(enforced) * 5 < nnz(candidate),
                "online pressure did not collapse distributed amplification: selected="
                        + nnz(enforced) + " all-inline=" + nnz(candidate));
        assertTrue(nnz(enforced) <= limits.csrHardTerms(),
                "public compiler exceeded its deterministic CSR cap");
    }

    @Test
    void ordinaryShape_reportsNoCompilerPressure() {
        var circuit = CircuitBuilder.create("diagnostics-no-pressure")
                .publicVar("out").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(api.mul(api.var("x"), api.var("y")),
                        api.var("out")));

        var compiled = circuit.compileR1CSWithDiagnostics(CurveId.BLS12_381);
        assertFalse(compiled.diagnostics().pressureModeEntered());
        assertEquals(compiled.system().constraints().size(), compiled.diagnostics().rows());
        assertEquals(nnz(compiled.system()), compiled.diagnostics().totalCsrTerms());
    }

    /**
     * Live terms alone are not a CPU bound: one 300-term expression copied through 5,000
     * single-use aliases keeps only ~300 terms live but performs ~1.5M input-term
     * copy/merge operations (plus result cleanup scans). The public compiler must enter
     * work-pressure mode and materialise the chain.
     */
    @Test
    void deepSingleUseChain_cumulativeWorkTriggersOnlineMaterialisation() {
        ConstraintGraph graph = deepSingleUseGraph(300, 5_000, false).constraintGraph();
        var unbounded = compile(graph, LinearInliningPolicy.select(graph, P));
        var bounded = R1CSCompiler.compile(graph, FIELD);

        assertEquals(1, unbounded.constraints().size(),
                "fixture must keep a single terminal row without the work budget");
        assertTrue(bounded.constraints().size() > unbounded.constraints().size(),
                "the cumulative-work guard did not materialise the deep copied expression");
        assertTrue(nnz(bounded) <= R1CSCompiler.resourceLimits(graph).csrHardTerms());
    }

    /**
     * Pressure preflights distinct operands before consuming any of them. Keep an {@code x+x}
     * boundary in the pressured suffix and prove the resulting public system rejects a
     * tampered output.
     */
    @Test
    void pressureMode_repeatedOperandRemainsSound() {
        var circuit = deepSingleUseGraph(300, 5_000, true);
        Map<String, List<BigInteger>> inputs = new java.util.HashMap<>();
        for (int i = 0; i < 300; i++) inputs.put("x" + i, List.of(BigInteger.ONE));
        inputs.put("out", List.of(BigInteger.valueOf(600)));

        BigInteger[] witness = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        var system = R1CSCompiler.compile(circuit.constraintGraph(), FIELD);
        var unbounded = compile(
                circuit.constraintGraph(),
                LinearInliningPolicy.select(circuit.constraintGraph(), P));
        assertTrue(system.constraints().size() > unbounded.constraints().size(),
                "fixture must enter pressure mode; otherwise the repeated-operand preflight "
                        + "guard is not exercised");
        assertTrue(satisfies(system, witness));

        BigInteger[] tampered = witness.clone();
        tampered[circuit.constraintGraph().publicInputs().getFirst().id()] =
                BigInteger.valueOf(601);
        assertFalse(satisfies(system, tampered),
                "pressure-mode x+x accepted a tampered public output");
    }

    /**
     * The amplification itself: the selected policy must remove it, not merely bound it. Under
     * all-inline the 500×500 shape reaches ~250,000 nonzeros for that one expression.
     */
    @Test
    void constantMulFanOut_amplificationIsRemoved() {
        var graph = graphOf(constantMulFanOut(500, 500), 500, 500);
        long inlineNnz = nnz(compile(graph, LinearInliningPolicy.inlineAll(graph)));
        long selectedNnz = nnz(compile(graph, LinearInliningPolicy.select(graph, P)));

        assertTrue(selectedNnz * 10 < inlineNnz,
                "expected the selected policy to cut nonzeros by well over 10x; all-inline="
                        + inlineNnz + " selected=" + selectedNnz);
    }

    @Test
    void pureAddFanOut_amplificationIsRemoved() {
        var graph = graphOf(pureAddFanOut(500, 500), 500, 500);
        long inlineNnz = nnz(compile(graph, LinearInliningPolicy.inlineAll(graph)));
        long selectedNnz = nnz(compile(graph, LinearInliningPolicy.select(graph, P)));

        assertTrue(selectedNnz * 10 < inlineNnz,
                "all-inline=" + inlineNnz + " selected=" + selectedNnz);
    }

    /** The row cost of removing it must be small — one row per materialised node, not many. */
    @Test
    void amplificationRemoval_costsFewRows() {
        var graph = graphOf(constantMulFanOut(500, 500), 500, 500);
        int inlineRows = compile(graph, LinearInliningPolicy.inlineAll(graph)).constraints().size();
        int selectedRows = compile(graph, LinearInliningPolicy.select(graph, P)).constraints().size();

        assertTrue(selectedRows - inlineRows <= 4,
                "expected at most a handful of extra rows, got " + (selectedRows - inlineRows));
    }

    // ------------------------------------------------------------------
    //  Production shapes must not regress against the incumbent
    // ------------------------------------------------------------------

    /**
     * The incumbent gate, stated directly rather than only through the Jubjub/Poseidon pins in
     * the other module: on shapes with ordinary fan-out the selected policy must produce
     * exactly the all-inline system, byte for byte in rows and nonzeros.
     */
    @Test
    void ordinaryFanOut_selectedPolicyMatchesIncumbentExactly() {
        for (int[] shape : new int[][]{{4, 4}, {10, 3}, {3, 10}, {16, 2}, {2, 16}, {8, 8}}) {
            var graph = graphOf(constantMulFanOut(shape[0], shape[1]), shape[0], shape[1]);
            var inline = compile(graph, LinearInliningPolicy.inlineAll(graph));
            var selected = compile(graph, LinearInliningPolicy.select(graph, P));

            assertEquals(inline.constraints().size(), selected.constraints().size(),
                    "rows regressed at T=" + shape[0] + " F=" + shape[1]);
            assertEquals(nnz(inline), nnz(selected),
                    "nonzeros differ at T=" + shape[0] + " F=" + shape[1]);
        }
    }

    @Test
    void singleUseExpression_isAlwaysInlined() {
        var graph = CircuitBuilder.create("single-use")
                .publicVar("out").secretVar("a").secretVar("b").secretVar("c")
                .define(api -> {
                    Variable wide = api.add(api.add(api.var("a"), api.var("b")), api.var("c"));
                    api.assertEqual(api.mul(wide, api.var("a")), api.var("out"));
                }).constraintGraph();

        assertEquals(compile(graph, LinearInliningPolicy.inlineAll(graph)).constraints().size(),
                compile(graph, LinearInliningPolicy.select(graph, P)).constraints().size());
    }

    // ------------------------------------------------------------------
    //  Differential satisfiability: all three policies accept the same witnesses
    // ------------------------------------------------------------------

    /**
     * The whole point of materialising is that it is semantics-preserving. Every policy must
     * accept exactly the witnesses the others do — including through zero, one and negative
     * constants, and through terms that cancel.
     */
    @Test
    void allPoliciesAgreeOnSatisfiability() {
        for (BigInteger k : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE),
                BigInteger.TWO, BigInteger.valueOf(7), P.subtract(BigInteger.TWO)}) {

            var circuit = CircuitBuilder.create("diff-" + k.mod(BigInteger.valueOf(1000)))
                    .publicVar("out").secretVar("a").secretVar("b")
                    .define(api -> {
                        Variable sum = api.add(api.var("a"), api.var("b"));
                        Variable scaled = api.mul(sum, api.constant(k));
                        // Read it several times so a materialisation decision is possible.
                        Variable acc = api.constant(0);
                        for (int i = 0; i < 6; i++) {
                            acc = api.add(acc, api.mul(scaled, api.var("a")));
                        }
                        api.assertEqual(acc, api.var("out"));
                    });

            BigInteger a = BigInteger.valueOf(3), b = BigInteger.valueOf(5);
            BigInteger expected = a.add(b).multiply(k).multiply(a)
                    .multiply(BigInteger.valueOf(6)).mod(P);

            var witness = circuit.calculateWitness(Map.of(
                    "out", List.of(expected), "a", List.of(a), "b", List.of(b)),
                    CurveId.BLS12_381);

            var graph = circuit.constraintGraph();
            for (var policy : List.of(
                    LinearInliningPolicy.inlineAll(graph),
                    LinearInliningPolicy.materialiseAll(graph, P),
                    LinearInliningPolicy.select(graph, P))) {
                assertTrue(satisfies(compile(graph, policy), witness),
                        "policy disagreed on satisfiability for k=" + k);
            }
        }
    }

    /** Term cancellation: {@code (a + b) - b} must collapse identically under every policy. */
    @Test
    void termCancellation_agreesAcrossPolicies() {
        var circuit = CircuitBuilder.create("cancellation")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    Variable sum = api.add(api.var("a"), api.var("b"));
                    Variable cancelled = api.sub(sum, api.var("b"));   // == a
                    Variable acc = api.constant(0);
                    for (int i = 0; i < 8; i++) {
                        acc = api.add(acc, api.mul(cancelled, api.var("b")));
                    }
                    api.assertEqual(acc, api.var("out"));
                });

        BigInteger a = BigInteger.valueOf(11), b = BigInteger.valueOf(13);
        var witness = circuit.calculateWitness(Map.of(
                        "out", List.of(a.multiply(b).multiply(BigInteger.valueOf(8)).mod(P)),
                        "a", List.of(a), "b", List.of(b)),
                CurveId.BLS12_381);

        var graph = circuit.constraintGraph();
        for (var policy : List.of(
                LinearInliningPolicy.inlineAll(graph),
                LinearInliningPolicy.materialiseAll(graph, P),
                LinearInliningPolicy.select(graph, P))) {
            assertTrue(satisfies(compile(graph, policy), witness));
        }
    }

    /** A materialised system must reject a witness the inlined one rejects. */
    @Test
    void allPoliciesRejectABadWitness() {
        var circuit = CircuitBuilder.create("reject")
                .publicVar("out").secretVar("a").secretVar("b")
                .define(api -> {
                    Variable sum = api.add(api.var("a"), api.var("b"));
                    Variable acc = api.constant(0);
                    for (int i = 0; i < 40; i++) {
                        acc = api.add(acc, api.mul(sum, api.var("a")));
                    }
                    api.assertEqual(acc, api.var("out"));
                });

        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(Map.of(
                        "out", List.of(BigInteger.valueOf(999999)),
                        "a", List.of(BigInteger.valueOf(3)),
                        "b", List.of(BigInteger.valueOf(5))),
                CurveId.BLS12_381));

        BigInteger a = BigInteger.valueOf(3), b = BigInteger.valueOf(5);
        BigInteger expected = a.add(b).multiply(a).multiply(BigInteger.valueOf(40)).mod(P);
        BigInteger[] valid = circuit.calculateWitness(Map.of(
                "out", List.of(expected), "a", List.of(a), "b", List.of(b)),
                CurveId.BLS12_381);
        BigInteger[] tampered = valid.clone();
        tampered[circuit.constraintGraph().publicInputs().getFirst().id()] =
                BigInteger.valueOf(999999);

        ConstraintGraph graph = circuit.constraintGraph();
        for (var policy : List.of(
                LinearInliningPolicy.inlineAll(graph),
                LinearInliningPolicy.materialiseAll(graph, P),
                LinearInliningPolicy.select(graph, P))) {
            assertFalse(satisfies(compile(graph, policy), tampered),
                    "compiled policy accepted a tampered public output");
        }
    }

    // ------------------------------------------------------------------
    //  Determinism
    // ------------------------------------------------------------------

    @Test
    void selectionIsDeterministic() {
        var graph = graphOf(constantMulFanOut(300, 300), 300, 300);
        var first = R1CSCompiler.compile(graph, FIELD);
        var second = R1CSCompiler.compile(graph, FIELD);

        assertEquals(first.constraints().size(), second.constraints().size());
        assertEquals(nnz(first), nnz(second));
        assertEquals(first.constraints(), second.constraints(),
                "same graph must produce byte-equivalent ordered sparse rows");
    }

    // ------------------------------------------------------------------
    //  Helpers
    // ------------------------------------------------------------------

    private static R1CSConstraintSystem compile(ConstraintGraph graph, LinearInliningPolicy policy) {
        return R1CSCompiler.compile(graph, FIELD, policy);
    }

    private static void assertWithinBaseline(ConstraintGraph graph) {
        var baseline = compile(graph, LinearInliningPolicy.materialiseAll(graph, P));
        var selected = R1CSCompiler.compile(graph, FIELD);

        assertTrue(selected.constraints().size() <= baseline.constraints().size(),
                "rows exceeded the materialise-all baseline: selected="
                        + selected.constraints().size() + " baseline=" + baseline.constraints().size());
        assertTrue(nnz(selected) <= nnz(baseline),
                "nonzeros exceeded the materialise-all baseline: selected=" + nnz(selected)
                        + " baseline=" + nnz(baseline));
    }

    private static ConstraintGraph distributedBinaryFanOutGraph(int terms, int depth) {
        var builder = CircuitBuilder.create("distributed-fanout");
        for (int i = 0; i < terms; i++) builder = builder.secretVar("x" + i);
        builder = builder.secretVar("y");

        return builder.define(api -> {
            Variable wide = api.constant(0);
            for (int i = 0; i < terms; i++) {
                wide = api.add(wide, api.var("x" + i));
            }

            List<Variable> frontier = List.of(wide);
            for (int level = 0; level < depth; level++) {
                List<Variable> next = new ArrayList<>(frontier.size() * 2);
                for (Variable parent : frontier) {
                    // Two distinct Add outputs make the parent's immediate fan-out exactly two.
                    next.add(api.add(parent, api.constant(0)));
                    next.add(api.add(parent, api.constant(0)));
                }
                frontier = next;
            }

            for (Variable leaf : frontier) {
                api.mul(leaf, api.var("y"));
            }
        }).constraintGraph();
    }

    private static CircuitBuilder deepSingleUseGraph(int terms, int depth, boolean assertOutput) {
        var builder = CircuitBuilder.create("deep-single-use");
        if (assertOutput) builder = builder.publicVar("out");
        for (int i = 0; i < terms; i++) builder = builder.secretVar("x" + i);

        return builder.define(api -> {
            Variable wide = api.constant(0);
            for (int i = 0; i < terms; i++) wide = api.add(wide, api.var("x" + i));
            for (int i = 0; i < depth; i++) wide = api.add(wide, api.constant(0));
            if (assertOutput) {
                api.assertEqual(api.add(wide, wide), api.var("out"));
            } else {
                api.mul(wide, api.var("x0"));
            }
        });
    }

    private static long nnz(R1CSConstraintSystem system) {
        long total = 0;
        for (var c : system.constraints()) {
            total += c.a().size() + c.b().size() + c.c().size();
        }
        return total;
    }

    /** Checks every row of the compiled system against a witness assignment. */
    private static boolean satisfies(R1CSConstraintSystem system, BigInteger[] witness) {
        for (var c : system.constraints()) {
            BigInteger a = dot(c.a(), witness);
            BigInteger b = dot(c.b(), witness);
            BigInteger cc = dot(c.c(), witness);
            if (!a.multiply(b).mod(P).equals(cc.mod(P))) return false;
        }
        return true;
    }

    private static BigInteger dot(Map<Integer, BigInteger> row, BigInteger[] witness) {
        BigInteger sum = BigInteger.ZERO;
        for (var e : row.entrySet()) {
            if (e.getKey() >= witness.length) return BigInteger.valueOf(-1);
            sum = sum.add(e.getValue().multiply(witness[e.getKey()])).mod(P);
        }
        return sum;
    }
}
