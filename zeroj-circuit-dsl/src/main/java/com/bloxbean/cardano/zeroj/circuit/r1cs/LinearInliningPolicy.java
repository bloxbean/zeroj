package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.circuit.ConstraintGraph;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Decides whether a derived linear expression is inlined into its readers or materialised as
 * one {@code (expression) · 1 = output} row.
 *
 * <p>Inlining keeps the row count and proving domain small, but copying a {@code T}-term
 * expression into {@code U} readers costs {@code T × U} sparse-matrix terms. Materialising
 * costs one row and approximately {@code T + U + 2} terms. The policy therefore materialises
 * only clear local amplification; {@link R1CSCompiler} separately enforces deterministic
 * global limits on emitted CSR terms, live expression-map terms, and cumulative map-copy work.
 *
 * <p>The decision is made <em>online</em> from the expression that emission actually built.
 * Earlier revisions replayed the complete all-inline graph to pre-plan decisions and then
 * replayed it again to measure a baseline. That doubled normal compile time and allocation,
 * added roughly 831 MB of planner arrays at 43.7M wires, and still failed to protect the
 * planning pass itself from distributed fan-out. Online selection restores the historical
 * one sparse-expression pass and lets the compiler enter pressure mode before live maps or
 * cumulative copy work exceed their budgets.
 */
final class LinearInliningPolicy {

    /** Never buy a row for a local heuristic saving smaller than this. */
    private static final long MIN_ABSOLUTE_SAVING = 64;

    /** A row is bought locally only when inlining is more than this much larger. */
    private static final long LOCAL_AMPLIFICATION_BUDGET = 32;

    private enum Mode {
        INLINE_ALL,
        MATERIALISE_ALL,
        HEURISTIC
    }

    private final Mode mode;

    private LinearInliningPolicy(Mode mode) {
        this.mode = Objects.requireNonNull(mode, "mode");
    }

    /** The historical policy, retained for differential tests. */
    static LinearInliningPolicy inlineAll(ConstraintGraph graph) {
        Objects.requireNonNull(graph, "graph");
        return new LinearInliningPolicy(Mode.INLINE_ALL);
    }

    /**
     * Materialises every live derived expression using its <em>actual current</em> size.
     * Unlike the withdrawn pre-planned baseline, this never emits a row for a dead output and
     * never materialises a downstream alias merely because its all-inline ancestor was wide.
     */
    static LinearInliningPolicy materialiseAll(ConstraintGraph graph, BigInteger ignoredPrime) {
        Objects.requireNonNull(graph, "graph");
        return new LinearInliningPolicy(Mode.MATERIALISE_ALL);
    }

    /** Fan-out-aware local candidate used by the public compiler. */
    static LinearInliningPolicy select(ConstraintGraph graph, BigInteger ignoredPrime) {
        Objects.requireNonNull(graph, "graph");
        return new LinearInliningPolicy(Mode.HEURISTIC);
    }

    /** Avoids any graph replay in the public compiler. */
    static LinearInliningPolicy select() {
        return new LinearInliningPolicy(Mode.HEURISTIC);
    }

    /**
     * Returns whether {@code expression} should be materialised.
     *
     * @param wireId output wire
     * @param termCount actual sparse term count after upstream decisions and cancellation
     * @param unconditionalInline true for multiplication by 0, 1, or -1
     * @param uses number of future reads of this newly-defined output
     * @param pressure whether the compiler has entered deterministic resource-pressure mode
     */
    boolean materialise(int wireId, int termCount, int uses,
                        boolean unconditionalInline, boolean pressure) {
        if (uses <= 0) return false;

        // Pressure mode collapses every expression that can amplify. Zero/single-term aliases
        // remain inline unless the compiler's separate live-entry cap is actually full; they
        // cannot amplify sparse terms and buying rows for a large alias tree would itself be
        // a row/domain regression.
        if (pressure) return termCount >= 2;

        if (termCount < 2 || unconditionalInline) return false;
        return switch (mode) {
            case INLINE_ALL -> false;
            case MATERIALISE_ALL -> true;
            case HEURISTIC -> locallyWorthMaterialising(termCount, uses);
        };
    }

    private static boolean locallyWorthMaterialising(long terms, long uses) {
        if (uses <= 0) return false;
        long inlineCost = saturatingMultiply(terms, uses);
        long materialiseCost = saturatingAdd(saturatingAdd(terms, uses), 2);
        return inlineCost > saturatingMultiply(materialiseCost, LOCAL_AMPLIFICATION_BUDGET)
                && inlineCost - materialiseCost >= MIN_ABSOLUTE_SAVING;
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
