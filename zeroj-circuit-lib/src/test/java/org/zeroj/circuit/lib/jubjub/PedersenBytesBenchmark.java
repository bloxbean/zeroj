package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * ADR-0058 M2 host performance matrix for {@code pedersen-jubjub-bytes-v1}. Records numbers and
 * asserts nothing: results are evidence for the exact JVM/CPU that ran them, not portable
 * constants. Generation (secret, blinded schedules) and disclosed verification (public path) are
 * reported separately and must not be compared as if they had the same security contract.
 * Run: {@code ./gradlew :zeroj-circuit-lib:pedersenBytesBenchmark}.
 */
@EnabledIfSystemProperty(named = "zeroj.pedersenBytesBench", matches = "true")
class PedersenBytesBenchmark {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long MIB = 1L << 20;
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    @Test
    @DisplayName("pedersen-jubjub-bytes-v1 host performance matrix")
    void matrix() throws Exception {
        if (THREADS.isThreadAllocatedMemorySupported()) {
            THREADS.setThreadAllocatedMemoryEnabled(true);
        }
        System.out.println("allocation accounting: " + (THREADS.isThreadAllocatedMemoryEnabled() ? "on" : "UNAVAILABLE (alloc/op invalid)"));
        System.out.printf("JVM %s %s, %s, %d cpus%n", System.getProperty("java.vm.name"),
                System.getProperty("java.vm.version"), System.getProperty("os.arch"),
                Runtime.getRuntime().availableProcessors());

        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        BigInteger s = PedersenCommitment.randomBlinding(RANDOM);
        JubjubPoint numeric = PedersenCommitment.commit(s, r);
        byte[] numericBytes = numeric.toBytes();

        // Fixed-size operations (µs/op), with allocation per op.
        warm(() -> PedersenCommitment.commit(s, r), 300);
        report("numeric commit (secret)", 300, () -> PedersenCommitment.commit(s, r));
        report("numeric verify (disclosed)", 300, () -> PedersenCommitment.verify(numeric, s, r));
        report("decode + subgroup check", 300, () -> PedersenCommitment.decode(numericBytes));
        report("randomBlinding", 2000, () -> PedersenCommitment.randomBlinding(RANDOM));

        // Payload-size matrix.
        for (long size : new long[]{0, 32, 1024, 8 * 1024, MIB, 16 * MIB}) {
            byte[] payload = PedersenBytesStreamTest.pattern((int) size);
            int iters = size <= 8 * 1024 ? 300 : size <= MIB ? 50 : 8;
            warm(() -> PedersenBytesHash.hashToScalar(payload), iters);
            report("hash/reduce array " + label(size), iters, () -> PedersenBytesHash.hashToScalar(payload));
            PedersenBytesCommitment c = PedersenCommitment.commitBytes(payload, r);
            report("commitBytes array " + label(size), iters, () -> PedersenCommitment.commitBytes(payload, r));
            report("commitBytes stream " + label(size), iters, () -> io(() ->
                    PedersenCommitment.commitBytes(new ByteArrayInputStream(payload), payload.length, r)));
            report("commitBytesToEnd stream " + label(size), iters, () -> io(() ->
                    PedersenCommitment.commitBytesToEnd(new ByteArrayInputStream(payload), payload.length, r)));
            report("verifyBytes prevalidated " + label(size), iters, () -> PedersenCommitment.verifyBytes(c, payload, r));
            byte[] wire = c.toPointBytes();
            report("verifyBytes received " + label(size), iters, () ->
                    PedersenCommitment.verifyBytes(PedersenBytesCommitment.decode(wire), payload, r));
        }
        long big = 256 * MIB;
        report("commitBytesToEnd generated 256 MiB", 3, () -> io(() ->
                PedersenCommitment.commitBytesToEnd(new PedersenBytesStreamTest.GeneratedStream(big), big, r)));
        report("generator only 256 MiB (input cost)", 3, () -> io(() -> drain(new PedersenBytesStreamTest.GeneratedStream(big))));

        // Raw digest throughput, SHA-256 (profile) vs SHA-512 (Q1 alternative).
        byte[] buf = new byte[8192];
        for (int i = 0; i < buf.length; i++) buf[i] = (byte) i;
        for (String alg : new String[]{"SHA-256", "SHA-512", "SHA-256", "SHA-512"}) {
            MessageDigest md = MessageDigest.getInstance(alg);
            long t = System.nanoTime();
            for (long done = 0; done < 256 * MIB; done += buf.length) md.update(buf);
            md.digest();
            System.out.printf("%-44s %8.0f MiB/s%n", "raw " + alg + " 256 MiB", 256 / ((System.nanoTime() - t) / 1e9));
        }

        // Concurrency: throughput at 1 and 8 workers for 1 MiB commitBytes.
        byte[] mib = PedersenBytesStreamTest.pattern((int) MIB);
        for (int workers : new int[]{1, 8}) {
            ExecutorService pool = Executors.newFixedThreadPool(workers);
            int perWorker = 40;
            long t = System.nanoTime();
            List<Future<?>> futures = new ArrayList<>();
            for (int w = 0; w < workers; w++) {
                futures.add(pool.submit(() -> {
                    for (int i = 0; i < perWorker; i++) PedersenCommitment.commitBytes(mib, r);
                }));
            }
            for (Future<?> f : futures) f.get();
            double secs = (System.nanoTime() - t) / 1e9;
            pool.shutdown();
            System.out.printf("%-44s %8.1f ops/s (%d workers)%n", "commitBytes 1 MiB concurrent", workers * perWorker / secs, workers);
        }
    }

    private interface IoOp {
        Object run() throws IOException;
    }

    private static Object io(IoOp op) {
        try {
            return op.run();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static Object drain(java.io.InputStream in) throws IOException {
        byte[] b = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(b, 0, b.length)) > 0) total += n;
        return total;
    }

    private static void warm(java.util.function.Supplier<?> op, int iters) {
        for (int i = 0; i < iters; i++) op.get();
    }

    private static void report(String name, int iters, java.util.function.Supplier<?> op) {
        long tid = Thread.currentThread().threadId();
        long[] samples = new long[iters];
        long allocBefore = THREADS.getThreadAllocatedBytes(tid);
        for (int i = 0; i < iters; i++) {
            long t = System.nanoTime();
            op.get();
            samples[i] = System.nanoTime() - t;
        }
        long alloc = (THREADS.getThreadAllocatedBytes(tid) - allocBefore) / iters;
        Arrays.sort(samples);
        System.out.printf("%-44s p50 %10.1f µs  p90 %10.1f µs  alloc/op %9d B%n", name,
                samples[iters / 2] / 1e3, samples[(int) (iters * 0.9)] / 1e3, alloc);
    }

    private static String label(long size) {
        return size >= MIB ? (size / MIB) + " MiB" : size >= 1024 ? (size / 1024) + " KiB" : size + " B";
    }
}
