package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * ADR-0055 M4 host performance of {@code confidential-note-jubjub-v1}: sealing, a failed trial
 * decryption, a full acceptance, a public reject, and parallel scanning, with heap allocated per
 * operation. Records numbers; asserts nothing. Results are evidence for the JVM and CPU that ran
 * them only, and make no timing-side-channel claim (ADR-0039).
 *
 * <p>Run: {@code ./gradlew :zeroj-circuit-lib:confidentialNoteBenchmark}
 */
@EnabledIfSystemProperty(named = "zeroj.noteBench", matches = "true")
class ConfidentialNoteBenchmark {

    private static final SecureRandom RNG = new SecureRandom();
    private static final com.sun.management.ThreadMXBean THREADS =
            (com.sun.management.ThreadMXBean) ManagementFactory.getThreadMXBean();

    /** Mean µs and allocated bytes per operation, after a warm-up of a quarter of {@code ops}. */
    private static double[] measure(int ops, Runnable body) {
        for (int i = 0; i < Math.max(1, ops / 4); i++) body.run();
        long thread = Thread.currentThread().threadId();
        long bytes = THREADS.getThreadAllocatedBytes(thread);
        long start = System.nanoTime();
        for (int i = 0; i < ops; i++) body.run();
        long elapsed = System.nanoTime() - start;
        long allocated = THREADS.getThreadAllocatedBytes(thread) - bytes;
        return new double[]{elapsed / 1_000.0 / ops, (double) allocated / ops};
    }

    private static void row(String label, double[] m) {
        System.out.printf("| %s | %.0f | %.1f |%n", label, m[0], m[1] / 1024.0);
    }

    @Test
    void matrix() throws Exception {
        NoteViewingKey owner = NoteViewingKey.generate(RNG);
        NoteViewingKey auditor = NoteViewingKey.generate(RNG);
        NoteViewingKey stranger = NoteViewingKey.generate(RNG);
        NoteOpening opening = NoteOpening.random(BigInteger.valueOf(1_000_000L), RNG);
        JubjubPoint c = opening.commitment();
        List<byte[]> deliveries = ConfidentialNotes.seal(opening, List.of(owner.readerKey(), auditor.readerKey()), RNG);
        byte[] mine = deliveries.get(0);
        NoteScanner ownerScanner = NoteScanner.of(owner);
        NoteScanner strangerScanner = NoteScanner.of(stranger);
        byte[] invalidE = mine.clone();
        System.arraycopy(JubjubPoint.IDENTITY.toBytes(), 0, invalidE, 0, 32);

        System.out.println("| Operation | µs/op | KiB allocated/op |");
        System.out.println("|---|---:|---:|");
        row("Viewing key generation (1 blinded multiplication)", measure(60, () -> NoteViewingKey.generate(RNG)));
        row("Seal, 1 reader (AEAD self-test + 2 blinded multiplications)",
                measure(40, () -> ConfidentialNotes.seal(opening, List.of(owner.readerKey()), RNG)));
        row("Seal, 2 readers (owner + auditor)",
                measure(30, () -> ConfidentialNotes.seal(opening, List.of(owner.readerKey(), auditor.readerKey()), RNG)));
        row("Open: full acceptance (Agree + KDF + AEAD + blinded commit)", measure(40, () -> ownerScanner.open(mine, c)));
        row("Open: failed trial, another reader's key (Agree + KDF + AEAD reject)", measure(60, () -> strangerScanner.open(mine, c)));
        row("Open: invalid E rejected before any secret work", measure(400, () -> ownerScanner.open(invalidE, c)));
        row("Open: wrong length rejected", measure(4000, () -> ownerScanner.open(Arrays.copyOf(mine, 88), c)));
        row("Scanner creation (AEAD known-answer self-test)", measure(400, () -> NoteScanner.of(owner)));
        row("AEAD self-test alone", measure(400, NoteAeadSelfTest::run));

        // Parallel scan: 512 notes for other readers, all failed trials, the dominant wallet cost.
        int notes = 512;
        List<byte[]> others = new ArrayList<>(notes);
        List<JubjubPoint> commitments = new ArrayList<>(notes);
        NoteReaderKey someoneElse = NoteViewingKey.generate(RNG).readerKey();
        for (int i = 0; i < notes; i++) {
            NoteOpening o = NoteOpening.random(BigInteger.valueOf(i), RNG);
            others.add(ConfidentialNotes.seal(o, List.of(someoneElse), RNG).get(0));
            commitments.add(o.commitment());
        }
        for (int threads : new int[]{1, 4, Runtime.getRuntime().availableProcessors()}) {
            ExecutorService pool = Executors.newFixedThreadPool(threads);
            try {
                scan(pool, threads, ownerScanner, others, commitments); // warm-up
                long start = System.nanoTime();
                scan(pool, threads, ownerScanner, others, commitments);
                double ms = (System.nanoTime() - start) / 1e6;
                System.out.printf("| Scan %d foreign notes, %d thread(s) | %.0f ms total, %.0f notes/s |%n",
                        notes, threads, ms, notes / (ms / 1000.0));
            } finally {
                pool.shutdown();
            }
        }
    }

    private static void scan(ExecutorService pool, int threads, NoteScanner scanner, List<byte[]> deliveries,
                             List<JubjubPoint> commitments) throws Exception {
        List<Future<?>> parts = new ArrayList<>();
        int n = deliveries.size();
        for (int t = 0; t < threads; t++) {
            int from = t * n / threads;
            int to = (t + 1) * n / threads;
            parts.add(pool.submit(() -> {
                for (int i = from; i < to; i++) {
                    if (scanner.open(deliveries.get(i), commitments.get(i)).isPresent()) {
                        throw new IllegalStateException("a foreign note opened");
                    }
                }
            }));
        }
        for (Future<?> f : parts) f.get();
    }
}
