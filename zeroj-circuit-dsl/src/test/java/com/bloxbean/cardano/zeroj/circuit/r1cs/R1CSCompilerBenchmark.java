package com.bloxbean.cardano.zeroj.circuit.r1cs;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.lang.management.ManagementFactory;
import java.util.Arrays;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Environment-sensitive compiler benchmark. Structural performance remains pinned in ordinary
 * tests; this records whether the online safety controller adds material time/allocation to a
 * stable 40k-row shape relative to the historical all-inline policy.
 */
@EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
class R1CSCompilerBenchmark {
    private static final int ROWS = 40_000;
    private static final int WARMUP = 3;
    private static final int SAMPLES = 9;

    @Test
    void publicCompilerOverheadAgainstIncumbent() {
        var circuit = CircuitBuilder.create("compiler-benchmark")
                .secretVar("x")
                .define(api -> {
                    Variable state = api.var("x");
                    for (int i = 0; i < ROWS; i++) {
                        state = api.add(
                                api.mul(state, state),
                                api.constant(i + 1L));
                    }
                    api.assertEqual(state, state);
                });
        var graph = circuit.constraintGraph();
        var incumbentPolicy = LinearInliningPolicy.inlineAll(graph);

        Supplier<R1CSConstraintSystem> incumbent =
                () -> R1CSCompiler.compile(graph, FieldConfig.BLS12_381, incumbentPolicy);
        Supplier<R1CSConstraintSystem> guarded =
                () -> R1CSCompiler.compile(graph, FieldConfig.BLS12_381);

        for (int i = 0; i < WARMUP; i++) {
            incumbent.get();
            guarded.get();
        }

        long[] incumbentNs = new long[SAMPLES];
        long[] guardedNs = new long[SAMPLES];
        long[] incumbentBytes = new long[SAMPLES];
        long[] guardedBytes = new long[SAMPLES];
        for (int i = 0; i < SAMPLES; i++) {
            // Alternate order so JIT/GC drift does not always favour one implementation.
            if ((i & 1) == 0) {
                sample(guarded, guardedNs, guardedBytes, i);
                sample(incumbent, incumbentNs, incumbentBytes, i);
            } else {
                sample(incumbent, incumbentNs, incumbentBytes, i);
                sample(guarded, guardedNs, guardedBytes, i);
            }
        }

        var incumbentSystem = incumbent.get();
        var guardedSystem = guarded.get();
        assertEquals(incumbentSystem.constraints(), guardedSystem.constraints(),
                "benchmark shape must remain structurally identical to the incumbent");

        Arrays.sort(incumbentNs);
        Arrays.sort(guardedNs);
        Arrays.sort(incumbentBytes);
        Arrays.sort(guardedBytes);
        double incumbentMs = incumbentNs[SAMPLES / 2] / 1e6;
        double guardedMs = guardedNs[SAMPLES / 2] / 1e6;
        long incumbentAllocation = incumbentBytes[SAMPLES / 2];
        long guardedAllocation = guardedBytes[SAMPLES / 2];

        System.out.printf("%n=== R1CS compiler 40k-row benchmark (median of %d) ===%n", SAMPLES);
        System.out.printf("JVM/OS       : %s %s; %s %s %s%n",
                System.getProperty("java.vm.name"), System.getProperty("java.version"),
                System.getProperty("os.name"), System.getProperty("os.version"),
                System.getProperty("os.arch"));
        System.out.printf("incumbent    : %.3f ms, %.1f MiB allocated%n",
                incumbentMs, incumbentAllocation / (1024.0 * 1024.0));
        System.out.printf("public guard : %.3f ms, %.1f MiB allocated%n",
                guardedMs, guardedAllocation / (1024.0 * 1024.0));
        System.out.printf("ratios       : %.3fx time, %.3fx allocation%n%n",
                guardedMs / incumbentMs,
                incumbentAllocation == 0 ? Double.NaN
                        : (double) guardedAllocation / incumbentAllocation);
    }

    private static void sample(
            Supplier<R1CSConstraintSystem> operation,
            long[] times,
            long[] allocations,
            int index) {
        com.sun.management.ThreadMXBean bean = allocationBean();
        long threadId = Thread.currentThread().threadId();
        long beforeBytes = bean == null ? 0 : bean.getThreadAllocatedBytes(threadId);
        long before = System.nanoTime();
        R1CSConstraintSystem result = operation.get();
        times[index] = System.nanoTime() - before;
        long afterBytes = bean == null ? 0 : bean.getThreadAllocatedBytes(threadId);
        allocations[index] = bean == null ? 0 : Math.max(0, afterBytes - beforeBytes);
        if (result.constraints().isEmpty()) {
            throw new IllegalStateException("benchmark compilation emitted no rows");
        }
    }

    private static com.sun.management.ThreadMXBean allocationBean() {
        var bean = ManagementFactory.getThreadMXBean();
        if (bean instanceof com.sun.management.ThreadMXBean allocating
                && allocating.isThreadAllocatedMemorySupported()) {
            if (!allocating.isThreadAllocatedMemoryEnabled()) {
                allocating.setThreadAllocatedMemoryEnabled(true);
            }
            return allocating;
        }
        return null;
    }
}
