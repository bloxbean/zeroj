package org.zeroj.bls12381.bulletproofs;

import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenOpening;
import org.zeroj.bls12381.spi.Bls12381Provider;
import org.zeroj.bls12381.spi.PureJavaBls12381Provider;

import java.io.BufferedReader;
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
 * ADR-0061 M3 / {@code commitment-profiles-v1} §15: standalone benchmark harness for
 * {@code bulletproof-range-bls12-381-g1-v1}. Records numbers and asserts nothing: results describe the
 * JVM, CPU and provider that ran them (ADR-0061 I11). Proving (offline/isolated, secret path) and
 * verification (public path) are reported separately.
 *
 * <p>The parent process launches {@value #FORKS} fresh JVMs ({@code --fork}); each warms up, then
 * measures every operation, and the parent prints the median across forks of each fork's p50 and
 * p95, with the allocation per operation on the calling thread. Throughput with 1 and 8 threads is
 * measured too. {@code --provider pure} (default) uses the pure-Java provider; {@code --provider blst}
 * loads {@code org.zeroj.blst.BlstBls12381Provider} reflectively, so this fixture does not depend on
 * {@code zeroj-blst}.
 *
 * <p>Run: {@code ./gradlew :zeroj-bls12381:bulletproofBenchmark} (pure Java) or
 * {@code ./gradlew :zeroj-blst:bulletproofBenchmarkBlst}. Test code only, never published.
 */
public final class BulletproofBenchmark {

    static final int FORKS = 3;
    private static final int[] WIDTHS = {16, 32, 64};
    private static final byte[] CTX = "https://example.com/zeroj/benchmark/v1".getBytes(StandardCharsets.US_ASCII);
    private static final SecureRandom RANDOM = new SecureRandom();
    /** Every result is written here, so the JIT cannot drop the measured work as unused. */
    private static volatile Object sink;
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    private BulletproofBenchmark() {
    }

    public static void main(String[] args) throws Exception {
        String provider = args.length >= 2 && args[0].equals("--provider") ? args[1]
                : args.length >= 3 && args[1].equals("--provider") ? args[2] : "pure";
        if (args.length > 0 && args[0].equals("--fork")) {
            fork(provider);
            return;
        }
        Bls12381Provider p = provider(provider);
        System.out.printf("JVM %s %s (%s), %s %s, %d cpus, %d forks, provider %s%n", System.getProperty("java.vm.name"),
                System.getProperty("java.vm.version"), System.getProperty("java.vendor"),
                System.getProperty("os.name"), System.getProperty("os.arch"),
                Runtime.getRuntime().availableProcessors(), FORKS, p.id());
        Map<String, List<double[]>> byOp = new LinkedHashMap<>();
        for (int f = 0; f < FORKS; f++) {
            Process proc = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "--enable-native-access=ALL-UNNAMED", "-cp", System.getProperty("java.class.path"),
                    BulletproofBenchmark.class.getName(), "--fork", "--provider", provider)
                    .redirectErrorStream(true).start();
            try (BufferedReader in = new BufferedReader(new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = in.readLine()) != null) {
                    if (!line.startsWith("RESULT\t")) {
                        if (line.startsWith("Exception") || line.contains("Error")) System.out.println(line);
                        continue;
                    }
                    String[] parts = line.split("\t");
                    byOp.computeIfAbsent(parts[1], k -> new ArrayList<>()).add(new double[] {
                            Double.parseDouble(parts[2]), Double.parseDouble(parts[3]), Double.parseDouble(parts[4])});
                }
            }
            if (proc.waitFor() != 0) {
                throw new IllegalStateException("fork " + f + " failed");
            }
        }
        System.out.printf("%-56s %14s %14s %16s%n", "operation", "p50", "p95", "alloc/op");
        for (var e : byOp.entrySet()) {
            double alloc = median(e.getValue(), 2);
            System.out.printf("%-56s %14s %14s %16s%n", e.getKey(), time(median(e.getValue(), 0)),
                    time(median(e.getValue(), 1)), alloc < 0 ? "n/a" : String.format("%,.0f B", alloc));
        }
    }

    static Bls12381Provider provider(String name) throws ReflectiveOperationException {
        return switch (name) {
            case "pure" -> PureJavaBls12381Provider.INSTANCE;
            case "blst" -> (Bls12381Provider) Class.forName("org.zeroj.blst.BlstBls12381Provider")
                    .getMethod("createDefault").invoke(null);
            default -> throw new IllegalArgumentException("--provider pure|blst");
        };
    }

    private static void fork(String providerName) throws Exception {
        if (THREADS.isThreadAllocatedMemorySupported()) {
            THREADS.setThreadAllocatedMemoryEnabled(true);
        }
        Bls12381Provider provider = provider(providerName);
        G1RangeProver prover = G1RangeProver.withProvider(provider);
        G1RangeVerifier verifier = G1RangeVerifier.withProvider(provider);
        G1Pedersen pedersen = G1Pedersen.withProvider(provider);
        for (int bits : WIDTHS) {
            BigInteger v = new BigInteger(bits, RANDOM);
            BigInteger gamma = G1Pedersen.randomBlinding(RANDOM);
            G1PedersenOpening opening = G1PedersenOpening.of(v, gamma);
            G1PedersenCommitment c = pedersen.commitScalar(v, gamma);
            G1RangeProof proof = prover.prove(opening, bits, CTX);
            byte[] wire = proof.toBytes();
            byte[] vWire = c.toPointBytes();
            if (!verifier.verify(c, proof, bits, CTX)) {
                throw new IllegalStateException("benchmark sanity: honest proof rejected");
            }
            int proveIterations = bits == 64 ? 6 : bits == 32 ? 8 : 12;
            int verifyIterations = bits == 64 ? 16 : bits == 32 ? 24 : 40;
            measure("prove n=" + bits + " (" + wire.length + " octets; secret path)", proveIterations,
                    () -> prover.prove(opening, bits, CTX));
            measure("decode n=" + bits + " (strict, every point subgroup-checked)", verifyIterations,
                    () -> G1RangeProof.decode(wire, bits));
            measure("verify n=" + bits + ", decoded proof and commitment", verifyIterations,
                    () -> verifier.verify(c, proof, bits, CTX));
            measure("verify n=" + bits + ", received octets (decode V and proof)", verifyIterations,
                    () -> verifier.verify(vWire, wire, bits, CTX));
            throughput("verify n=" + bits + " received octets", 8, bits == 64 ? 3 : 6,
                    () -> verifier.verify(vWire, wire, bits, CTX));
        }
        if (sink == null) {
            throw new IllegalStateException("benchmark sanity");
        }
    }

    /** Warms up, then reports p50, p95 (nanoseconds) and bytes allocated per operation on this thread. */
    private static void measure(String name, int iterations, Op op) throws Exception {
        for (int i = 0; i < Math.max(2, iterations / 3); i++) {
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

    /** Wall time per operation with 1 and with {@code threads} threads. */
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
                long perOp = (System.nanoTime() - t0) / ((long) t * perThread);
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

    @FunctionalInterface
    private interface Op {
        Object run() throws Exception;
    }
}
