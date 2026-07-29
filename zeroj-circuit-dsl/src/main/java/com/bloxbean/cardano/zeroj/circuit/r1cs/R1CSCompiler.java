package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.circuit.ConstraintGraph;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Gate;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Compiles a {@link ConstraintGraph} into an {@link R1CSConstraintSystem}.
 *
 * <p>Additions and constant multiplications are normally folded into downstream linear
 * combinations. ADR-0038 adds online materialisation for expressions whose fan-out would
 * amplify sparse matrices, plus deterministic resource pressure limits. The compiler still
 * performs the historical two graph traversals: one integer-only read/resource pre-pass and
 * one sparse-expression emission pass. It does not replay all-inline or materialise-all maps.
 *
 * <h2>Resource safety</h2>
 * Three different resources are bounded independently:
 * <ul>
 *   <li>packed CSR terms (including per-matrix signed-int capacity);</li>
 *   <li>live HashMap expression terms/entries, whose byte cost is much higher than CSR;</li>
 *   <li>a cumulative input-term copy/merge work proxy, which catches a wide single-use
 *       expression copied through a deep chain even when its live frontier stays small.
 *       HashMap result-cleanup scans add at most a small constant factor and are not counted
 *       as exact visits.</li>
 * </ul>
 *
 * <p>Approaching any soft limit enters pressure mode. Before a gate reads any operand, every
 * distinct stored operand is materialised, and every subsequent live derived value is
 * materialised on definition. This collapses the suffix to graph-linear work without
 * discarding a partially-built CSR or changing decisions based on machine heap size. Limits
 * are fixed/versioned constants, so the same graph compiles to the same R1CS everywhere.
 */
public final class R1CSCompiler {

    /** Roughly 4.2 GB at ADR-0034's conservative 12-byte packed-term estimate. */
    private static final long MAX_TOTAL_CSR_TERMS = 350_000_000L;

    /** Each CSR matrix is indexed by signed ints in {@link R1CSFlat}. */
    private static final long MAX_MATRIX_TERMS = Integer.MAX_VALUE - 8L;

    /** Keep boxed/HashMap live-frontier storage below roughly a few hundred MB. */
    private static final long MAX_LIVE_EXPRESSION_TERMS = 1_000_000L;
    private static final long MAX_LIVE_EXPRESSION_ENTRIES = 250_000L;

    /** Deterministic graph-relative soft limits; absolute caps above still win. */
    private static final long CSR_STRUCTURAL_MULTIPLIER = 32;
    private static final long WORK_STRUCTURAL_MULTIPLIER = 64;
    private static final long LIVE_STRUCTURAL_MULTIPLIER = 4;

    private R1CSCompiler() {}

    /** Compile with online fan-out selection and deterministic resource-pressure repair. */
    public static R1CSConstraintSystem compile(ConstraintGraph graph, FieldConfig config) {
        return compileWithDiagnostics(graph, config).system();
    }

    /**
     * Compiles with the public policy and returns deterministic structural diagnostics.
     *
     * <p>Pressure mode is semantics-preserving but may materialise a different expression set,
     * changing the R1CS fingerprint and therefore its circuit-specific setup/keys. Ordinary
     * callers may keep using {@link #compile}; deployment/build tooling that wants to surface
     * that event should use this method and record {@link CompilationDiagnostics#pressureModeEntered()}.
     *
     * <p>This is an additive API rather than a new component on {@link R1CSConstraintSystem}:
     * changing that public record's canonical shape would be a source and binary compatibility
     * break for every existing constructor call.
     */
    public static CompilationResult compileWithDiagnostics(
            ConstraintGraph graph, FieldConfig config) {
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(config, "config");
        graph.requireCompatibleField(config);
        Analysis analysis = analyze(graph);
        ResourceBudget budget = ResourceBudget.bounded(analysis);
        R1CSConstraintSystem system = compileInternal(
                graph, config, LinearInliningPolicy.select(), analysis.reads(), budget);
        return new CompilationResult(system, budget.diagnostics());
    }

    /**
     * Compile under an explicit policy. Package-private for differential tests; deliberately
     * unbounded so tests can measure the historical all-inline and aggressive policies.
     */
    static R1CSConstraintSystem compile(ConstraintGraph graph, FieldConfig config,
                                        LinearInliningPolicy policy) {
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(config, "config");
        Objects.requireNonNull(policy, "policy");
        graph.requireCompatibleField(config);
        return compileInternal(
                graph, config, policy, analyze(graph).reads(), ResourceBudget.unbounded());
    }

    /** Exact emitted row/term metrics under an explicit policy, retaining no CSR rows. */
    static Metrics measure(ConstraintGraph graph, BigInteger p, LinearInliningPolicy policy) {
        Objects.requireNonNull(graph, "graph");
        Objects.requireNonNull(p, "p");
        Objects.requireNonNull(policy, "policy");
        CountingSink sink = new CountingSink();
        emit(graph, p, policy, sink, analyze(graph).reads(), ResourceBudget.unbounded());
        return sink.metrics();
    }

    /** Deterministic limits exposed package-private for load-bearing structural tests. */
    static ResourceLimits resourceLimits(ConstraintGraph graph) {
        return ResourceBudget.bounded(analyze(graph)).limits();
    }

    private static R1CSConstraintSystem compileInternal(
            ConstraintGraph graph,
            FieldConfig config,
            LinearInliningPolicy policy,
            int[] reads,
            ResourceBudget budget) {
        FlatSink sink = new FlatSink(budget);
        emit(graph, config.prime(), policy, sink, reads, budget);
        return sink.toSystem(graph, config);
    }

    /**
     * One integer-only graph pre-pass. It replaces both the old read-count traversal and the
     * withdrawn all-inline planning/materialise-all measurement passes.
     */
    static Analysis analyze(ConstraintGraph graph) {
        Objects.requireNonNull(graph, "graph");
        int[] reads = new int[graph.numWires()];
        long csrReserve = 1;
        long workReserve = 1;

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) -> {
                    // In pressure mode even a constant may be pinned to release its map entry.
                    csrReserve = saturatingAdd(csrReserve, 3);
                    workReserve = saturatingAdd(workReserve, 1);
                }
                case Gate.Add(var out, var left, var right) -> {
                    incrementRead(reads, left.id());
                    incrementRead(reads, right.id());
                    // At pressure, operands are base wires: at most 2 + one + output.
                    csrReserve = saturatingAdd(csrReserve, 4);
                    workReserve = saturatingAdd(workReserve, 4);
                }
                case Gate.LinComb(var out, var terms) -> {
                    for (var term : terms) incrementRead(reads, term.variable().id());
                    csrReserve = saturatingAdd(
                            csrReserve, saturatingAdd(terms.size(), 2L));
                    workReserve = saturatingAdd(
                            workReserve, saturatingAdd(saturatingMultiply(terms.size(), 2), 1));
                }
                case Gate.Mul(var out, var left, var right) -> {
                    incrementRead(reads, left.id());
                    incrementRead(reads, right.id());
                    csrReserve = saturatingAdd(csrReserve, 3);
                    workReserve = saturatingAdd(workReserve, 4);
                }
                case Gate.AssertEq(var left, var right) -> {
                    incrementRead(reads, left.id());
                    incrementRead(reads, right.id());
                    csrReserve = saturatingAdd(csrReserve, 3);
                    workReserve = saturatingAdd(workReserve, 4);
                }
                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) ->
                        throw rawSelectUnsupported();
                default -> {
                    // Hints/decompositions add no R1CS row themselves; their callers emit the
                    // binding rows as ordinary gates.
                    workReserve = saturatingAdd(workReserve, 1);
                }
            }
        }
        return new Analysis(reads, csrReserve, workReserve,
                Math.max(1L, graph.gates().size()));
    }

    /**
     * Counts one future expression read without allowing the signed counter to wrap. A
     * negative wrapped count would make {@link #place} classify a live derived value as dead
     * and later consumers would treat its wire as an unconstrained base variable.
     */
    static void incrementRead(int[] reads, int wireId) {
        Objects.requireNonNull(reads, "reads");
        if (wireId < 0 || wireId >= reads.length) {
            throw new IllegalArgumentException(
                    "gate references wire " + wireId + " outside [0, "
                            + reads.length + ")");
        }
        if (reads[wireId] == Integer.MAX_VALUE) {
            throw new IllegalStateException(
                    "wire " + wireId + " exceeds the signed-int expression read-count "
                            + "capacity; split the graph");
        }
        reads[wireId]++;
    }

    /**
     * Shared single-pass emission engine. Resource estimates are checked before consuming
     * operands, so multi-operand consumers reject/repair atomically rather than after one
     * operand has already changed the expression frontier.
     */
    private static void emit(
            ConstraintGraph graph,
            BigInteger p,
            LinearInliningPolicy policy,
            RowSink sink,
            int[] reads,
            ResourceBudget budget) {
        ExpressionStore expressions = new ExpressionStore(reads, budget);
        int oneWire = graph.oneWire().id();
        Map<Integer, BigInteger> one = Map.of(oneWire, BigInteger.ONE);

        for (var gate : graph.gates()) {
            switch (gate) {
                case Gate.Const(var out, var value) ->
                        place(sink, expressions, policy, budget, oneWire, out.id(),
                                Map.of(oneWire, value.mod(p)), true);

                case Gate.Add(var out, var left, var right) -> {
                    budget.beforeWork(saturatingAdd(
                            expressions.termCount(left.id()),
                            expressions.termCount(right.id())));
                    materialiseOperandsIfPressured(
                            expressions, sink, budget, oneWire, left.id(), right.id());

                    var leftExpr = expressions.consume(left.id());
                    var rightExpr = expressions.consume(right.id());
                    budget.recordWork(saturatingAdd(leftExpr.size(), rightExpr.size()));
                    place(sink, expressions, policy, budget, oneWire, out.id(),
                            addExprs(leftExpr, rightExpr, p), false);
                }

                case Gate.LinComb(var out, var terms) -> {
                    long estimatedWork = 0;
                    for (var term : terms) {
                        estimatedWork = saturatingAdd(
                                estimatedWork, expressions.termCount(term.variable().id()));
                    }
                    budget.beforeWork(estimatedWork);
                    if (budget.pressure()) {
                        // Repeated ids are harmless: the first call removes a stored
                        // expression, and later calls become no-ops. Avoid a HashSet and
                        // temporary int[] on every LinComb in a pressured large-circuit suffix.
                        for (var term : terms) {
                            expressions.materialiseStored(
                                    term.variable().id(), sink, oneWire);
                        }
                    }

                    Map<Integer, BigInteger> combined = new HashMap<>();
                    long actualWork = 0;
                    for (var term : terms) {
                        var termExpr = expressions.consume(term.variable().id());
                        actualWork = saturatingAdd(actualWork, termExpr.size());
                        for (var entry : termExpr.entrySet()) {
                            combined.merge(entry.getKey(),
                                    entry.getValue().multiply(term.coefficient()).mod(p),
                                    (a, b) -> a.add(b).mod(p));
                        }
                    }
                    combined.values().removeIf(v -> v.signum() == 0);
                    budget.recordWork(actualWork);
                    place(sink, expressions, policy, budget, oneWire, out.id(), combined, false);
                }

                case Gate.Mul(var out, var left, var right) -> {
                    var aPeek = expressions.peek(left.id());
                    var bPeek = expressions.peek(right.id());
                    BigInteger aConst = constantValue(aPeek, oneWire);
                    BigInteger bConst = constantValue(bPeek, oneWire);
                    if (aConst != null || bConst != null) {
                        Map<Integer, BigInteger> source = bConst != null ? aPeek : bPeek;
                        budget.beforeWork(source.size());
                    } else {
                        budget.beforePotentialRow(
                                saturatingAdd(saturatingAdd(aPeek.size(), bPeek.size()), 1));
                    }
                    materialiseOperandsIfPressured(
                            expressions, sink, budget, oneWire, left.id(), right.id());

                    var a = expressions.consume(left.id());
                    var b = expressions.consume(right.id());
                    aConst = constantValue(a, oneWire);
                    bConst = constantValue(b, oneWire);
                    if (bConst != null) {
                        budget.recordWork(a.size());
                        place(sink, expressions, policy, budget, oneWire, out.id(),
                                scaleExpr(a, bConst, p), isTrivialFactor(bConst, p));
                    } else if (aConst != null) {
                        budget.recordWork(b.size());
                        place(sink, expressions, policy, budget, oneWire, out.id(),
                                scaleExpr(b, aConst, p), isTrivialFactor(aConst, p));
                    } else {
                        sink.add(a, b, Map.of(out.id(), BigInteger.ONE));
                        expressions.remove(out.id());
                    }
                }

                case Gate.AssertEq(var left, var right) -> {
                    long operandTerms = saturatingAdd(
                            expressions.termCount(left.id()),
                            expressions.termCount(right.id()));
                    budget.beforeWork(operandTerms);
                    budget.beforePotentialRow(saturatingAdd(operandTerms, 1));
                    materialiseOperandsIfPressured(
                            expressions, sink, budget, oneWire, left.id(), right.id());

                    var leftExpr = expressions.consume(left.id());
                    var rightExpr = expressions.consume(right.id());
                    budget.recordWork(saturatingAdd(leftExpr.size(), rightExpr.size()));
                    var diff = subExprs(leftExpr, rightExpr, p);
                    if (!diff.isEmpty()) {
                        sink.add(diff, one, Map.of());
                    }
                }

                case Gate.Select(var out, var cond, var ifTrue, var ifFalse) ->
                        throw rawSelectUnsupported();

                case Gate.BitDecompose(var outputs, var input, var nBits) -> {
                    for (var output : outputs) expressions.remove(output.id());
                }

                case Gate.Hint(var out, var type, var input) ->
                        expressions.remove(out.id());

                case Gate.HintN(var outputs, var kind, var inputs, var params) -> {
                    for (var output : outputs) expressions.remove(output.id());
                }
            }
        }
    }

    /**
     * Materialises stored operands before any is consumed. Repeated ids are harmless because
     * materialisation removes the stored expression and subsequent calls are no-ops. This is
     * essential for {@code x+x}: doing it after the first consume could evict the expression
     * before the second read and change the relation.
     */
    private static void materialiseOperandsIfPressured(
            ExpressionStore expressions,
            RowSink sink,
            ResourceBudget budget,
            int oneWire,
            int... wireIds) {
        if (!budget.pressure()) return;
        for (int wireId : wireIds) {
            expressions.materialiseStored(wireId, sink, oneWire);
        }
    }

    /**
     * Stores or materialises a derived expression. Dead outputs are discarded entirely.
     * Pressure is checked before insertion, so the live frontier never grows past its soft cap.
     */
    private static void place(
            RowSink sink,
            ExpressionStore expressions,
            LinearInliningPolicy policy,
            ResourceBudget budget,
            int oneWire,
            int outId,
            Map<Integer, BigInteger> expression,
            boolean unconditionalInline) {
        int uses = expressions.remainingReads(outId);
        if (uses <= 0) return;

        boolean liveCapRequiresMaterialisation = budget.beforeStore(
                expressions.liveTerms(), expressions.liveEntries(), expression.size());
        boolean materialise = policy.materialise(
                outId, expression.size(), uses, unconditionalInline, budget.pressure())
                || liveCapRequiresMaterialisation;
        if (materialise) {
            budget.beforePotentialRow(saturatingAdd(expression.size(), 2));
            sink.add(expression, Map.of(oneWire, BigInteger.ONE),
                    Map.of(outId, BigInteger.ONE));
        } else {
            expressions.put(outId, expression);
        }
    }

    private static boolean isTrivialFactor(BigInteger factor, BigInteger p) {
        BigInteger reduced = factor.mod(p);
        return reduced.signum() == 0
                || reduced.equals(BigInteger.ONE)
                || reduced.equals(p.subtract(BigInteger.ONE));
    }

    /** Sparse structural metrics, using longs so accounting cannot wrap at int scale. */
    record Metrics(long rows, long nonZeros) {
        Metrics {
            if (rows < 0 || nonZeros < 0) {
                throw new IllegalArgumentException("R1CS metrics must be non-negative");
            }
        }
    }

    /**
     * Public structural diagnostics for one compiler invocation. These values are deterministic
     * for a graph/compiler version; they are not wall-clock or heap measurements.
     */
    public record CompilationDiagnostics(
            boolean pressureModeEntered,
            long rows,
            long totalCsrTerms,
            long cumulativeExpressionWorkTerms) {
        public CompilationDiagnostics {
            if (rows < 0 || totalCsrTerms < 0 || cumulativeExpressionWorkTerms < 0) {
                throw new IllegalArgumentException("compiler diagnostics must be non-negative");
            }
        }
    }

    /** Compiled system plus the diagnostics from the same single emission pass. */
    public record CompilationResult(
            R1CSConstraintSystem system,
            CompilationDiagnostics diagnostics) {
        public CompilationResult {
            Objects.requireNonNull(system, "system");
            Objects.requireNonNull(diagnostics, "diagnostics");
        }
    }

    /** Integer-only pre-pass result. The reads array is consumed exactly once by emission. */
    record Analysis(int[] reads, long csrReserve, long workReserve, long graphScale) {}

    /** Fixed/versioned public-compile limits, exposed to package tests. */
    record ResourceLimits(
            long csrSoftTerms,
            long csrHardTerms,
            long liveTermSoftLimit,
            long liveEntrySoftLimit,
            long workSoftTerms,
            long workHardTerms) {}

    private interface RowSink {
        void add(Map<Integer, BigInteger> a,
                 Map<Integer, BigInteger> b,
                 Map<Integer, BigInteger> c);
    }

    private static final class CountingSink implements RowSink {
        private long rows;
        private long nonZeros;

        @Override
        public void add(Map<Integer, BigInteger> a,
                        Map<Integer, BigInteger> b,
                        Map<Integer, BigInteger> c) {
            rows = Math.addExact(rows, 1);
            nonZeros = Math.addExact(nonZeros,
                    Math.addExact((long) a.size(),
                            Math.addExact((long) b.size(), c.size())));
        }

        Metrics metrics() {
            return new Metrics(rows, nonZeros);
        }
    }

    private static final class FlatSink implements RowSink {
        private final R1CSFlat.Builder builder = R1CSFlat.builder();
        private final ResourceBudget budget;

        FlatSink(ResourceBudget budget) {
            this.budget = budget;
        }

        @Override
        public void add(Map<Integer, BigInteger> a,
                        Map<Integer, BigInteger> b,
                        Map<Integer, BigInteger> c) {
            budget.recordRow(a.size(), b.size(), c.size());
            builder.add(a, b, c);
        }

        R1CSConstraintSystem toSystem(ConstraintGraph graph, FieldConfig config) {
            R1CSFlat flat = builder.build();
            return new R1CSConstraintSystem(config, graph.numWires(),
                    graph.publicInputs().size(), graph.secretInputs().size(),
                    flat.asList(), flat);
        }
    }

    /** Tracks mutable expression-map state and its real live frontier. */
    private static final class ExpressionStore {
        private final Map<Integer, Map<Integer, BigInteger>> expressions = new HashMap<>();
        private final int[] remainingReads;
        private final ResourceBudget budget;
        private long liveTerms;
        private long liveEntries;

        ExpressionStore(int[] remainingReads, ResourceBudget budget) {
            this.remainingReads = Objects.requireNonNull(remainingReads, "remainingReads");
            this.budget = Objects.requireNonNull(budget, "budget");
        }

        int remainingReads(int wireId) {
            return remainingReads[wireId];
        }

        long liveTerms() {
            return liveTerms;
        }

        long liveEntries() {
            return liveEntries;
        }

        int termCount(int wireId) {
            Map<Integer, BigInteger> expression = expressions.get(wireId);
            return expression == null ? 1 : expression.size();
        }

        Map<Integer, BigInteger> peek(int wireId) {
            Map<Integer, BigInteger> expression = expressions.get(wireId);
            return expression != null ? expression : Map.of(wireId, BigInteger.ONE);
        }

        Map<Integer, BigInteger> consume(int wireId) {
            Map<Integer, BigInteger> expression = expressions.get(wireId);
            if (--remainingReads[wireId] <= 0 && expression != null) {
                remove(wireId);
            }
            return expression != null ? expression : Map.of(wireId, BigInteger.ONE);
        }

        void put(int wireId, Map<Integer, BigInteger> expression) {
            Map<Integer, BigInteger> old = expressions.put(wireId, expression);
            if (old != null) {
                liveTerms -= old.size();
            } else {
                liveEntries++;
            }
            liveTerms = Math.addExact(liveTerms, expression.size());
            budget.assertLiveWithinHardLimit(liveTerms, liveEntries);
        }

        void remove(int wireId) {
            Map<Integer, BigInteger> removed = expressions.remove(wireId);
            if (removed != null) {
                liveTerms -= removed.size();
                liveEntries--;
            }
        }

        void materialiseStored(int wireId, RowSink sink, int oneWire) {
            Map<Integer, BigInteger> expression = expressions.get(wireId);
            // A zero/single-term alias cannot amplify a downstream sparse expression. Keep it
            // inline; place() will materialise new aliases only if the live-entry cap itself
            // is full.
            if (expression == null || expression.size() < 2) return;
            budget.beforePotentialRow(saturatingAdd(expression.size(), 2));
            sink.add(expression, Map.of(oneWire, BigInteger.ONE),
                    Map.of(wireId, BigInteger.ONE));
            remove(wireId);
        }
    }

    /**
     * Deterministic pressure controller. Soft limits change the materialisation plan; hard
     * limits are representation/resource safety checks and fail explicitly if even aggressive
     * suffix materialisation cannot fit.
     */
    private static final class ResourceBudget {
        private final boolean bounded;
        private final long csrSoft;
        private final long csrHard;
        private final long liveTermsSoft;
        private final long liveEntriesSoft;
        private final long workSoft;
        private final long workHard;

        private boolean pressure;
        private long aTerms;
        private long bTerms;
        private long cTerms;
        private long totalTerms;
        private long workTerms;
        private long rows;

        private ResourceBudget(
                boolean bounded,
                long csrSoft,
                long csrHard,
                long liveTermsSoft,
                long liveEntriesSoft,
                long workSoft,
                long workHard) {
            this.bounded = bounded;
            this.csrSoft = csrSoft;
            this.csrHard = csrHard;
            this.liveTermsSoft = liveTermsSoft;
            this.liveEntriesSoft = liveEntriesSoft;
            this.workSoft = workSoft;
            this.workHard = workHard;
        }

        static ResourceBudget unbounded() {
            return new ResourceBudget(false,
                    Long.MAX_VALUE, Long.MAX_VALUE,
                    Long.MAX_VALUE, Long.MAX_VALUE,
                    Long.MAX_VALUE, Long.MAX_VALUE);
        }

        static ResourceBudget bounded(Analysis analysis) {
            long liveTermSoft = Math.min(
                    MAX_LIVE_EXPRESSION_TERMS,
                    saturatingMultiply(
                            analysis.graphScale(), LIVE_STRUCTURAL_MULTIPLIER));
            long liveEntrySoft = Math.min(
                    MAX_LIVE_EXPRESSION_ENTRIES,
                    saturatingMultiply(
                            analysis.graphScale(), LIVE_STRUCTURAL_MULTIPLIER));

            // Reserve enough CSR space to pin the complete live frontier and aggressively
            // materialise every remaining gate after pressure starts.
            long repairReserve = saturatingAdd(
                    analysis.csrReserve(),
                    saturatingAdd(liveTermSoft, saturatingMultiply(liveEntrySoft, 2)));
            long factorSoft = saturatingMultiply(
                    analysis.csrReserve(), CSR_STRUCTURAL_MULTIPLIER);
            long absoluteSoft = Math.max(0, MAX_TOTAL_CSR_TERMS - repairReserve);
            long csrSoft = Math.min(factorSoft, absoluteSoft);
            long csrHard = Math.min(
                    MAX_TOTAL_CSR_TERMS, saturatingAdd(csrSoft, repairReserve));

            long workSoft = saturatingMultiply(
                    analysis.workReserve(), WORK_STRUCTURAL_MULTIPLIER);
            long workHard = saturatingAdd(workSoft, analysis.workReserve());
            return new ResourceBudget(true, csrSoft, csrHard,
                    liveTermSoft, liveEntrySoft, workSoft, workHard);
        }

        ResourceLimits limits() {
            return new ResourceLimits(
                    csrSoft, csrHard, liveTermsSoft, liveEntriesSoft, workSoft, workHard);
        }

        CompilationDiagnostics diagnostics() {
            return new CompilationDiagnostics(pressure, rows, totalTerms, workTerms);
        }

        boolean pressure() {
            return pressure;
        }

        void beforeWork(long additional) {
            if (bounded && !pressure && exceeds(workTerms, additional, workSoft)) {
                pressure = true;
            }
        }

        void recordWork(long additional) {
            workTerms = checkedAdd(
                    workTerms, additional, "cumulative expression input-term work");
            if (bounded && !pressure && workTerms > workSoft) pressure = true;
            if (bounded && workTerms > workHard) {
                throw resourceLimit(
                        "cumulative expression input-term work", workTerms, workHard);
            }
        }

        void beforePotentialRow(long terms) {
            if (bounded && !pressure && exceeds(totalTerms, terms, csrSoft)) {
                pressure = true;
            }
        }

        boolean beforeStore(long currentTerms, long currentEntries, long newTerms) {
            if (!bounded) return false;
            boolean wouldExceed = exceeds(currentTerms, newTerms, liveTermsSoft)
                    || currentEntries >= liveEntriesSoft;
            if (wouldExceed) pressure = true;
            return wouldExceed;
        }

        void assertLiveWithinHardLimit(long terms, long entries) {
            if (!bounded) return;
            // place() checks before insertion. Reaching here above the soft cap means a caller
            // bypassed pressure-aware placement, which is a compiler bug rather than an input
            // condition.
            if (terms > liveTermsSoft || entries > liveEntriesSoft) {
                throw new IllegalStateException(
                        "R1CS compiler live-expression accounting exceeded its deterministic "
                                + "limit after placement (terms=" + terms + "/"
                                + liveTermsSoft + ", entries=" + entries + "/"
                                + liveEntriesSoft + ")");
            }
        }

        void recordRow(long a, long b, long c) {
            aTerms = checkedAdd(aTerms, a, "R1CS A-matrix terms");
            bTerms = checkedAdd(bTerms, b, "R1CS B-matrix terms");
            cTerms = checkedAdd(cTerms, c, "R1CS C-matrix terms");
            totalTerms = checkedAdd(totalTerms,
                    checkedAdd(a, checkedAdd(b, c, "row terms"), "row terms"),
                    "total CSR terms");
            rows = checkedAdd(rows, 1, "R1CS rows");

            if (aTerms > MAX_MATRIX_TERMS
                    || bTerms > MAX_MATRIX_TERMS
                    || cTerms > MAX_MATRIX_TERMS) {
                throw new IllegalStateException(
                        "R1CS matrix exceeds signed-int CSR capacity: A=" + aTerms
                                + ", B=" + bTerms + ", C=" + cTerms
                                + ", max=" + MAX_MATRIX_TERMS);
            }
            if (rows >= Integer.MAX_VALUE) {
                throw new IllegalStateException(
                        "R1CS row count exceeds signed-int CSR capacity: " + rows);
            }
            if (bounded && !pressure && totalTerms > csrSoft) pressure = true;
            if (bounded && totalTerms > csrHard) {
                throw resourceLimit("packed CSR terms", totalTerms, csrHard);
            }
        }

        private static boolean exceeds(long current, long additional, long limit) {
            return additional > limit || current > limit - additional;
        }

        private static long checkedAdd(long left, long right, String what) {
            try {
                return Math.addExact(left, right);
            } catch (ArithmeticException e) {
                throw new IllegalStateException(what + " overflowed 64-bit accounting", e);
            }
        }

        private static IllegalStateException resourceLimit(
                String resource, long actual, long limit) {
            return new IllegalStateException(
                    "R1CS compilation exceeded the deterministic " + resource
                            + " limit (" + actual + " > " + limit + "). "
                            + "The compiler already switched to aggressive materialisation; "
                            + "split the circuit or revise the versioned resource policy.");
        }
    }

    /**
     * If an expression is a pure constant (its only term is the one-wire), return the value.
     * The empty map is constant zero.
     */
    static BigInteger constantValue(Map<Integer, BigInteger> expression, int oneWireId) {
        if (expression.isEmpty()) return BigInteger.ZERO;
        if (expression.size() != 1) return null;
        var entry = expression.entrySet().iterator().next();
        return entry.getKey() == oneWireId ? entry.getValue() : null;
    }

    static Map<Integer, BigInteger> scaleExpr(
            Map<Integer, BigInteger> expression, BigInteger factor, BigInteger p) {
        BigInteger reduced = factor.mod(p);
        if (reduced.signum() == 0) return Map.of();
        var result = new HashMap<Integer, BigInteger>(hashCapacity(expression.size()));
        for (var entry : expression.entrySet()) {
            BigInteger value = entry.getValue().multiply(reduced).mod(p);
            if (value.signum() != 0) result.put(entry.getKey(), value);
        }
        return result;
    }

    static Map<Integer, BigInteger> addExprs(
            Map<Integer, BigInteger> a,
            Map<Integer, BigInteger> b,
            BigInteger p) {
        var result = new HashMap<>(a);
        for (var entry : b.entrySet()) {
            result.merge(entry.getKey(), entry.getValue(),
                    (left, right) -> left.add(right).mod(p));
        }
        result.values().removeIf(value -> value.signum() == 0);
        return result;
    }

    static Map<Integer, BigInteger> subExprs(
            Map<Integer, BigInteger> a,
            Map<Integer, BigInteger> b,
            BigInteger p) {
        var result = new HashMap<>(a);
        for (var entry : b.entrySet()) {
            result.merge(entry.getKey(), entry.getValue().negate().mod(p),
                    (left, right) -> left.add(right).mod(p));
        }
        result.values().removeIf(value -> value.signum() == 0);
        return result;
    }

    private static int hashCapacity(int size) {
        return (int) Math.min(1L << 30, Math.max(16L, (long) size * 2));
    }

    private static UnsupportedOperationException rawSelectUnsupported() {
        return new UnsupportedOperationException(
                "Select gate must be decomposed into booleanity, multiplication, and addition "
                        + "constraints before R1CS compilation. CircuitAPI.select performs "
                        + "that expansion; a raw public Gate.Select is rejected rather than "
                        + "leaving its output unconstrained.");
    }

    private static long saturatingAdd(long a, long b) {
        if (a > Long.MAX_VALUE - b) return Long.MAX_VALUE;
        return a + b;
    }

    private static long saturatingMultiply(long a, long b) {
        if (a == 0 || b == 0) return 0;
        if (a > Long.MAX_VALUE / b) return Long.MAX_VALUE;
        return a * b;
    }
}
