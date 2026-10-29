package org.zeroj.bls12381.pedersen;

import org.zeroj.api.commitment.CommitmentEnvelope;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * ADR-0060 M5 / {@code commitment-profiles-v1} §15: standalone Java benchmark harness for the G1
 * Pedersen profiles. Records numbers and asserts nothing: results describe the JVM and CPU that ran
 * them, not portable constants. Generation (offline/isolated, secret path) and disclosed verification
 * (public path) are reported separately and are not comparable as if they had the same contract.
 *
 * <p>The parent process launches {@value #FORKS} fresh JVMs ({@code --fork}), each warming up and then
 * measuring every operation; it prints the median across forks of each fork's p50 and p95, and the
 * allocation per operation. Single-thread and eight-thread throughput are both measured.
 *
 * <p>Measures the pure-Java provider. Run: {@code ./gradlew :zeroj-bls12381:g1PedersenBenchmark}.
 */
final class G1PedersenBenchmark {

    static final int FORKS = 3;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long MIB = 1L << 20;
    /** Every result is written here, so the JIT cannot drop the measured work as unused. */
    private static volatile Object sink;
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    private G1PedersenBenchmark() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length > 0 && args[0].equals("--fork")) {
            fork();
            return;
        }
        System.out.printf("JVM %s %s (%s), %s %s, %d cpus, %d forks%n", System.getProperty("java.vm.name"),
                System.getProperty("java.vm.version"), System.getProperty("java.vendor"),
                System.getProperty("os.name"), System.getProperty("os.arch"),
                Runtime.getRuntime().availableProcessors(), FORKS);
        Map<String, List<double[]>> byOp = new LinkedHashMap<>();
        for (int f = 0; f < FORKS; f++) {
            Process p = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-cp", System.getProperty("java.class.path"), G1PedersenBenchmark.class.getName(), "--fork")
                    .redirectErrorStream(true).start();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (!line.startsWith("RESULT\t")) {
                        continue;
                    }
                    String[] parts = line.split("\t");
                    byOp.computeIfAbsent(parts[1], k -> new ArrayList<>()).add(new double[] {
                            Double.parseDouble(parts[2]), Double.parseDouble(parts[3]), Double.parseDouble(parts[4])});
                }
            }
            if (p.waitFor() != 0) {
                throw new IllegalStateException("fork " + f + " failed");
            }
        }
        System.out.printf("%-48s %14s %14s %16s%n", "operation", "p50", "p95", "alloc/op");
        for (var e : byOp.entrySet()) {
            double p50 = median(e.getValue(), 0);
            double p95 = median(e.getValue(), 1);
            double alloc = median(e.getValue(), 2);
            System.out.printf("%-48s %14s %14s %16s%n", e.getKey(), time(p50), time(p95),
                    alloc < 0 ? "n/a" : String.format("%,.0f B", alloc));
        }
    }

    private static void fork() throws Exception {
        if (THREADS.isThreadAllocatedMemorySupported()) {
            THREADS.setThreadAllocatedMemoryEnabled(true);
        }
        G1Pedersen pedersen = G1Pedersen.pureJava();
        BigInteger m = G1Pedersen.randomBlinding(RANDOM);
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment c = pedersen.commitScalar(m, r);
        byte[] wire = c.toPointBytes();
        byte[] envelope = CommitmentEnvelope.encode(c);

        measure("commitScalar (generation, secret path)", 60, () -> pedersen.commitScalar(m, r));
        measure("decode (strict, subgroup check)", 100, () -> G1PedersenCommitment.decode(wire));
        measure("verifyScalar prevalidated (V1)", 60, () -> pedersen.verifyScalar(c, m, r));
        measure("decode + verifyScalar received (V1)", 60,
                () -> pedersen.verifyScalar(G1PedersenCommitment.decode(wire), m, r));
        measure("withPublicDelta 64-bit (V3)", 60, () -> c.withPublicDelta(BigInteger.valueOf(-123_456_789L), 64));
        measure("add (V3 sum term)", 2000, () -> c.add(c));
        measure("envelope encode + decode", 100,
                () -> CommitmentEnvelope.decode(CommitmentEnvelope.encode(c), G1PedersenCommitment.CODEC));
        measure("randomBlinding", 5000, () -> G1Pedersen.randomBlinding(RANDOM));
        for (long size : new long[] {0, 1024, MIB, 16 * MIB}) {
            byte[] payload = new byte[(int) size];
            RANDOM.nextBytes(payload);
            int iterations = size <= 1024 ? 60 : size <= MIB ? 20 : 5;
            measure("bytes map " + label(size), iterations * 4, () -> G1PedersenBytesHash.hashToScalar(payload));
            measure("commitBytes " + label(size), iterations, () -> pedersen.commitBytes(payload, r));
            G1PedersenBytesCommitment b = pedersen.commitBytes(payload, r);
            measure("verifyBytes " + label(size), iterations, () -> pedersen.verifyBytes(b, payload, r));
        }
        throughput("commitScalar", 8, 40, () -> pedersen.commitScalar(m, r));
        throughput("decode + verifyScalar", 8, 40, () -> pedersen.verifyScalar(G1PedersenCommitment.decode(wire), m, r));
        if (envelope.length != 74 || sink == null) {
            throw new IllegalStateException("benchmark sanity");
        }
    }

    /** Warms up, then reports p50, p95 (nanoseconds) and bytes allocated per operation on this thread. */
    private static void measure(String name, int iterations, Op op) throws Exception {
        for (int i = 0; i < Math.max(5, iterations / 2); i++) {
            sink = op.run();
        }
        long[] samples = new long[iterations];
        long allocBefore = allocated();
        for (int i = 0; i < iterations; i++) {
            long t0 = System.nanoTime();
            sink = op.run();
            samples[i] = System.nanoTime() - t0;
        }
        long allocAfter = allocated();
        Arrays.sort(samples);
        double alloc = allocBefore < 0 ? -1 : (double) (allocAfter - allocBefore) / iterations;
        System.out.printf("RESULT\t%s\t%d\t%d\t%.0f%n", name, samples[iterations / 2],
                samples[Math.min(iterations - 1, (int) Math.ceil(iterations * 0.95) - 1)], alloc);
    }

    /** Operations per second with one thread and with {@code threads} threads (reported as p50 = time per op). */
    private static void throughput(String name, int threads, int perThread, Op op) throws Exception {
        for (int t : new int[] {1, threads}) {
            ExecutorService pool = Executors.newFixedThreadPool(t);
            try {
                List<Future<?>> futures = new ArrayList<>();
                long t0 = System.nanoTime();
                for (int i = 0; i < t; i++) {
                    futures.add(pool.submit(() -> {
                        for (int k = 0; k < perThread; k++) {
                            sink = op.run();
                        }
                        return null;
                    }));
                }
                for (Future<?> f : futures) {
                    f.get();
                }
                long elapsed = System.nanoTime() - t0;
                long perOp = elapsed / ((long) t * perThread);
                System.out.printf("RESULT\t%s, %d thread(s), wall time per op\t%d\t%d\t-1%n", name, t, perOp, perOp);
            } finally {
                pool.shutdownNow();
            }
        }
    }

    private static long allocated() {
        return THREADS.isThreadAllocatedMemoryEnabled() ? THREADS.getCurrentThreadAllocatedBytes() : -1;
    }

    private static double median(List<double[]> rows, int column) {
        double[] v = rows.stream().mapToDouble(row -> row[column]).sorted().toArray();
        return v[v.length / 2];
    }

    private static String time(double nanos) {
        return nanos >= 1e6 ? String.format("%,.2f ms", nanos / 1e6) : String.format("%,.1f µs", nanos / 1e3);
    }

    private static String label(long size) {
        return size >= MIB ? (size / MIB) + " MiB" : size >= 1024 ? (size / 1024) + " KiB" : size + " B";
    }

    @FunctionalInterface
    private interface Op {
        Object run() throws IOException;
    }
}
