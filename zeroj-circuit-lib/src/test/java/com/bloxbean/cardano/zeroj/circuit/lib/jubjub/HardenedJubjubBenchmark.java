package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Recorded ADR-0039 M6 benchmark. No latency threshold is asserted before the secure baseline
 * and deployment target are reviewed.
 */
@EnabledIfSystemProperty(named = "zeroj.hardenedBench", matches = "true")
class HardenedJubjubBenchmark {

    private static final int WARMUP = 80;
    private static final int SAMPLES = 400;

    @Test
    void recordMatrix() throws Exception {
        printPlatform();
        BigInteger sk = new BigInteger(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                16).mod(JubjubCurve.SUBGROUP_ORDER);
        JubjubMessage message = JubjubMessage.hashToField(
                "ADR-0039 hardened benchmark".getBytes());
        EdDSAJubjub.Keypair legacyKey = EdDSAJubjub.keypairFromSecret(sk);
        EdDSAJubjub.Signature publicSignature = EdDSAJubjub.sign(
                legacyKey, message.toPublicFieldElement());

        try (HardenedJubjubKey deterministicKey =
                     HardenedJubjubKey.importCanonical(fixed32(sk));
             JubjubSigner deterministic =
                     JubjubSigners.fixedLimbDeterministicV1Compatibility(
                             deterministicKey);
             HardenedJubjubKey hedgedKey =
                     HardenedJubjubKey.importCanonical(fixed32(sk));
             JubjubSigner hedged = JubjubSigners.hedgedCandidateForTesting(
                     hedgedKey, JubjubSigners.sourceForTesting(new SecureRandom()));
             HardenedPedersenOpening opening =
                     HardenedPedersenOpening.fromUnsigned(
                             fixed32(BigInteger.valueOf(42)), 256,
                             fixed32(JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE)),
                             256)) {

            report("legacy sign(Keypair,msg)",
                    () -> EdDSAJubjub.sign(legacyKey, message.toPublicFieldElement()));
            report("fixed deterministic-v1 sign", () -> deterministic.sign(message));
            report("fixed hedged candidate sign", () -> hedged.sign(message));
            report("public verify", () -> EdDSAJubjub.verify(
                    legacyKey.pk(), message, publicSignature));
            report("legacy Pedersen commit", () -> PedersenCommitment.commit(
                    BigInteger.valueOf(42),
                    JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE)));
            report("fixed Pedersen candidate", () -> HardenedPedersen.commit(opening));
            report("hardened key import", () -> {
                HardenedJubjubKey key = HardenedJubjubKey.importCanonical(fixed32(sk));
                key.close();
                return key;
            });
        }
    }

    @Test
    void recordConcurrentScaling() throws Exception {
        printPlatform();
        BigInteger sk = BigInteger.valueOf(0x390039);
        JubjubMessage message = JubjubMessage.hashToField(
                "ADR-0039 concurrent benchmark".getBytes());
        for (int threads : new int[]{1, 2, 4, 8}) {
            try (HardenedJubjubKey key =
                         HardenedJubjubKey.importCanonical(fixed32(sk));
                 JubjubSigner signer = JubjubSigners.hedgedCandidateForTesting(
                         key, JubjubSigners.sourceForTesting(new SecureRandom()))) {
                var executor = Executors.newFixedThreadPool(threads);
                CountDownLatch ready = new CountDownLatch(threads);
                CountDownLatch start = new CountDownLatch(1);
                int warmupPerThread = 25;
                int operationsPerThread = 200;
                List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
                try {
                    for (int thread = 0; thread < threads; thread++) {
                        futures.add(executor.submit(() -> {
                            for (int i = 0; i < warmupPerThread; i++) {
                                signer.sign(message);
                            }
                            ready.countDown();
                            start.await();
                            for (int i = 0; i < operationsPerThread; i++) {
                                signer.sign(message);
                            }
                            return null;
                        }));
                    }
                    assertTrue(ready.await(5, TimeUnit.SECONDS));
                    long begin = System.nanoTime();
                    start.countDown();
                    executor.shutdown();
                    assertTrue(executor.awaitTermination(60, TimeUnit.SECONDS));
                    for (var future : futures) {
                        future.get();
                    }
                    double seconds = (System.nanoTime() - begin) / 1_000_000_000.0;
                    int operations = threads * operationsPerThread;
                    System.out.printf(
                            "hedged concurrency threads=%d throughput=%8.2f sig/s "
                                    + "wall=%7.3f ms/op%n",
                            threads, operations / seconds, seconds * 1_000.0 / operations);
                } finally {
                    start.countDown();
                    executor.shutdownNow();
                }
            }
        }
    }

    private static <T> void report(String name, Callable<T> operation) throws Exception {
        for (int i = 0; i < WARMUP; i++) {
            operation.call();
        }
        long beforeAllocation = allocatedBytes();
        long[] samples = new long[SAMPLES];
        T last = null;
        for (int i = 0; i < samples.length; i++) {
            long start = System.nanoTime();
            last = operation.call();
            samples[i] = System.nanoTime() - start;
        }
        long afterAllocation = allocatedBytes();
        Arrays.sort(samples);
        double median = micros(samples[samples.length / 2]);
        double p95 = micros(samples[(int) (samples.length * 0.95)]);
        double p99 = micros(samples[(int) (samples.length * 0.99)]);
        double allocation = beforeAllocation >= 0 && afterAllocation >= beforeAllocation
                ? (afterAllocation - beforeAllocation) / (double) samples.length
                : Double.NaN;
        System.out.printf(
                "%-34s median=%9.3f us  p95=%9.3f us  p99=%9.3f us  "
                        + "alloc=%9.1f B/op%n",
                name, median, p95, p99, allocation);
        assertTrue(last != null);
    }

    private static long allocatedBytes() {
        var bean = ManagementFactory.getThreadMXBean();
        if (bean instanceof com.sun.management.ThreadMXBean threadBean
                && threadBean.isThreadAllocatedMemorySupported()) {
            if (!threadBean.isThreadAllocatedMemoryEnabled()) {
                threadBean.setThreadAllocatedMemoryEnabled(true);
            }
            return threadBean.getThreadAllocatedBytes(Thread.currentThread().threadId());
        }
        return -1L;
    }

    private static double micros(long nanos) {
        return nanos / 1_000.0;
    }

    private static void printPlatform() {
        System.out.println("java.version=" + System.getProperty("java.version"));
        System.out.println("java.vm.name=" + System.getProperty("java.vm.name"));
        System.out.println("java.vm.version=" + System.getProperty("java.vm.version"));
        System.out.println("os.name=" + System.getProperty("os.name"));
        System.out.println("os.arch=" + System.getProperty("os.arch"));
        System.out.println("availableProcessors="
                + Runtime.getRuntime().availableProcessors());
        System.out.println("jvm.arguments="
                + ManagementFactory.getRuntimeMXBean().getInputArguments());
        System.out.println("gc="
                + ManagementFactory.getGarbageCollectorMXBeans().stream()
                .map(bean -> bean.getName())
                .toList());
        SecureRandom random = new SecureRandom();
        System.out.println("defaultSecureRandom.algorithm=" + random.getAlgorithm());
        System.out.println("defaultSecureRandom.provider="
                + random.getProvider().getName() + "/" + random.getProvider().getVersionStr());
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length == 33 && raw[0] == 0 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }
}
