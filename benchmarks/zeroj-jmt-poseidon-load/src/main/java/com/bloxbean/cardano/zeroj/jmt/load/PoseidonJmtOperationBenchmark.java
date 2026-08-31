package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/** Measures update, rollback, reopen, and pruning without mutating the retained load database. */
public final class PoseidonJmtOperationBenchmark {
    private final JmtLoadOptions options;
    private final JmtRunFiles files;

    public PoseidonJmtOperationBenchmark(JmtLoadOptions options) {
        this.options = options;
        files = new JmtRunFiles(options.workDir());
    }

    public OperationResult run() throws IOException {
        JmtRunFiles.Manifest manifest = files.ensureManifest(options);
        if (manifest.completedEntries() != options.entries()) {
            throw new IllegalStateException("JMT load must be complete before operation benchmark");
        }
        byte[] baselineRoot = HexFormat.of().parseHex(manifest.rootHex());
        validateRetainedBaseline(baselineRoot);
        Path operationScratch = Files.createTempDirectory(
                options.workDir(), "operation-update-scratch-");
        try {
            return runOnScratch(operationScratch, baselineRoot);
        } finally {
            deleteOperationScratch(operationScratch);
        }
    }

    private OperationResult runOnScratch(Path operationScratch, byte[] baselineRoot)
            throws IOException {
        Path scratchDatabase = operationScratch.resolve("rocksdb");
        long copyStarted = System.nanoTime();
        copyDatabase(files.rocksDbDir(), scratchDatabase);
        double scratchCopySeconds = elapsed(copyStarted);
        long scratchDatabaseBytes = JmtRunFiles.directoryBytes(scratchDatabase);
        byte[] baselineKey = DeterministicJmtDataset.key(options.seed(), 0);
        byte[] originalValue = DeterministicJmtDataset.value(options.seed(), 0);
        byte[] proofKey;
        byte[] proofValue;
        Map<byte[], byte[]> updates = new LinkedHashMap<>(
                Math.max(16, options.operationEntries() * 4 / 3 + 1));
        byte[] updatedValue = originalValue.clone();
        updatedValue[updatedValue.length - 1] ^= 0x5a;
        updates.put(baselineKey, updatedValue);
        proofKey = baselineKey;
        proofValue = updatedValue;
        for (int operation = 1; operation < options.operationEntries(); operation++) {
            long datasetIndex = Math.addExact(options.entries(), operation);
            proofKey = DeterministicJmtDataset.key(options.seed(), datasetIndex);
            proofValue = DeterministicJmtDataset.value(options.seed(), datasetIndex);
            updates.put(proofKey, proofValue);
        }

        double updateSeconds;
        double proofSeconds;
        int proofBytes;
        double rollbackSeconds;
        long updateVersion = Math.addExact(options.entries(), 1);
        try (HeapSampler resources = new HeapSampler()) {
            try (RocksDbJmtStore store = RocksDbJmtStore.open(
                    scratchDatabase.toString(), options.storeOptions())) {
                PoseidonJmtTree tree = new PoseidonJmtTree(store, options.pairCacheEntries());
                var latest = store.latestRoot().orElseThrow();
                requireBaseline(latest.version(), latest.rootHash(), baselineRoot);

                long updateStarted = System.nanoTime();
                byte[] updatedRoot = tree.put(updateVersion, updates).rootHash();
                updateSeconds = elapsed(updateStarted);
                long proofStarted = System.nanoTime();
                var proof = tree.getProof(proofKey, updateVersion).orElseThrow();
                byte[] wire = tree.encodeProof(proofKey, proof);
                proofSeconds = elapsed(proofStarted);
                proofBytes = wire.length;
                if (!tree.verifyInclusionProof(updatedRoot, proofKey, proofValue, proof)
                        || !tree.verifyProofWire(updatedRoot, proofKey, proofValue, true, wire)) {
                    throw new IllegalStateException("Post-update JMT proof failed verification");
                }

                long rollbackStarted = System.nanoTime();
                store.truncateAfter(options.entries());
                rollbackSeconds = elapsed(rollbackStarted);
                var restored = store.latestRoot().orElseThrow();
                requireBaseline(restored.version(), restored.rootHash(), baselineRoot);
                var restoredProof = tree.getProof(baselineKey, options.entries()).orElseThrow();
                if (!tree.verifyInclusionProof(
                        baselineRoot, baselineKey, originalValue, restoredProof)) {
                    throw new IllegalStateException(
                            "JMT rollback did not restore the baseline statement");
                }
            }

            OperationResult result = finishAfterClose(
                    scratchDatabase, baselineRoot, baselineKey, originalValue, updateVersion,
                    scratchCopySeconds, scratchDatabaseBytes,
                    updateSeconds, proofSeconds, proofBytes, rollbackSeconds,
                    resources);
            files.writeReportSection("operations", result, options);
            return result;
        }
    }

    private OperationResult finishAfterClose(
            Path scratchDatabase,
            byte[] baselineRoot,
            byte[] baselineKey,
            byte[] originalValue,
            long updateVersion,
            double scratchCopySeconds,
            long scratchDatabaseBytes,
            double updateSeconds,
            double proofSeconds,
            int proofBytes,
            double rollbackSeconds,
            HeapSampler resources) throws IOException {
        long reopenStarted = System.nanoTime();
        try (RocksDbJmtStore reopened = RocksDbJmtStore.open(
                scratchDatabase.toString(), options.storeOptions())) {
            PoseidonJmtTree tree = new PoseidonJmtTree(reopened);
            var latest = reopened.latestRoot().orElseThrow();
            requireBaseline(latest.version(), latest.rootHash(), baselineRoot);
            if (!tree.verifyInclusionProof(
                    baselineRoot, baselineKey, originalValue,
                    tree.getProof(baselineKey, options.entries()).orElseThrow())) {
                throw new IllegalStateException("Reopened JMT proof failed verification");
            }
        }
        double reopenSeconds = elapsed(reopenStarted);

        PruneResult prune = runPruneScratch();
        OperationResult result = new OperationResult(
                Instant.now().toString(), updateVersion, options.operationEntries(),
                scratchCopySeconds, scratchDatabaseBytes,
                updateSeconds, options.operationEntries() / Math.max(updateSeconds, 0.000_001),
                proofSeconds, proofBytes, rollbackSeconds, reopenSeconds, prune,
                resources.peakBytes(), resources.peakRssBytes(),
                resources.peakRssMinusUsedHeapBytes(), resources.rssSamples(),
                resources.rssSource());
        return result;
    }

    private void validateRetainedBaseline(byte[] baselineRoot) throws IOException {
        try (RocksDbJmtStore retained = RocksDbJmtStore.open(
                files.rocksDbDir().toString(), options.storeOptions())) {
            var latest = retained.latestRoot().orElseThrow();
            requireBaseline(latest.version(), latest.rootHash(), baselineRoot);
        }
    }

    private static void copyDatabase(Path source, Path target) throws IOException {
        Files.walkFileTree(source, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes)
                    throws IOException {
                if (Files.isSymbolicLink(directory)) {
                    throw new IOException("JMT database copy refuses symbolic-link directories");
                }
                Path relative = source.relativize(directory);
                Files.createDirectories(target.resolve(relative));
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                    throws IOException {
                if (!attributes.isRegularFile() || Files.isSymbolicLink(file)) {
                    throw new IOException("JMT database copy accepts only regular files: " + file);
                }
                Files.copy(file, target.resolve(source.relativize(file)),
                        StandardCopyOption.COPY_ATTRIBUTES);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private void deleteOperationScratch(Path scratch) throws IOException {
        Path parent = options.workDir().toAbsolutePath().normalize();
        Path candidate = scratch.toAbsolutePath().normalize();
        if (!candidate.getParent().equals(parent)
                || !candidate.getFileName().toString().startsWith("operation-update-scratch-")) {
            throw new IOException("refusing to delete an unrecognized operation scratch path");
        }
        Files.walkFileTree(candidate, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
                    throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path directory, IOException error)
                    throws IOException {
                if (error != null) throw error;
                Files.delete(directory);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private PruneResult runPruneScratch() throws IOException {
        Path scratch = options.workDir().resolve("operation-scratch-" + System.currentTimeMillis());
        Files.createDirectories(scratch);
        long bytesBefore;
        long bytesAfter;
        long pruned;
        double pruneSeconds;
        byte[] latestRoot;
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                scratch.toString(), options.storeOptions())) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            for (long version = 1; version <= 20; version++) {
                Map<byte[], byte[]> updates = new LinkedHashMap<>();
                for (int key = 0; key < 64; key++) {
                    byte[] value = DeterministicJmtDataset.value(version, key);
                    updates.put(DeterministicJmtDataset.key(9001L, key), value);
                }
                tree.put(version, updates);
            }
            latestRoot = store.latestRoot().orElseThrow().rootHash();
            bytesBefore = JmtRunFiles.directoryBytes(scratch);
            long pruneStarted = System.nanoTime();
            pruned = store.pruneUpTo(15);
            pruneSeconds = elapsed(pruneStarted);
            bytesAfter = JmtRunFiles.directoryBytes(scratch);
            var latest = store.latestRoot().orElseThrow();
            if (latest.version() != 20 || !Arrays.equals(latestRoot, latest.rootHash())) {
                throw new IllegalStateException("Prune changed the retained JMT head");
            }
            byte[] proofKey = DeterministicJmtDataset.key(9001L, 0);
            byte[] proofValue = DeterministicJmtDataset.value(20, 0);
            if (!tree.verifyInclusionProof(latestRoot, proofKey, proofValue,
                    tree.getProof(proofKey, 20).orElseThrow())) {
                throw new IllegalStateException("Retained JMT proof failed after prune");
            }
        }
        return new PruneResult(
                scratch.toString(), 20, 15, pruned, pruneSeconds, bytesBefore, bytesAfter);
    }

    private void requireBaseline(long version, byte[] actualRoot, byte[] expectedRoot) {
        if (version != options.entries() || !Arrays.equals(actualRoot, expectedRoot)) {
            throw new IllegalStateException("JMT operation benchmark baseline mismatch");
        }
    }

    private static double elapsed(long started) {
        return (System.nanoTime() - started) / 1_000_000_000.0;
    }

    public record OperationResult(
            String completedAt,
            long temporaryUpdateVersion,
            int updateEntries,
            double scratchDatabaseCopySeconds,
            long scratchDatabaseBytes,
            double updateSeconds,
            double updateEntriesPerSecond,
            double updatedProofSeconds,
            int updatedProofBytes,
            double rollbackSeconds,
            double reopenAndVerifySeconds,
            PruneResult prune,
            long peakObservedHeapBytes,
            long peakObservedRssBytes,
            long peakRssMinusUsedHeapBytes,
            long rssSamples,
            String rssSource) {}

    public record PruneResult(
            String retainedScratchDirectory,
            long latestVersion,
            long horizon,
            long recordsPruned,
            double pruneSeconds,
            long databaseBytesBefore,
            long databaseBytesAfter) {}
}
