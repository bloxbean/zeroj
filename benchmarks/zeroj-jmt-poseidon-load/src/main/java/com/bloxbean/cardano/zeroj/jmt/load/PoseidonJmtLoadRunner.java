package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;

import java.io.IOException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

public final class PoseidonJmtLoadRunner {
    private final JmtLoadOptions options;
    private final JmtRunFiles files;
    private final CheckpointObserver checkpointObserver;

    public PoseidonJmtLoadRunner(JmtLoadOptions options) {
        this(options, (completed, root) -> {});
    }

    PoseidonJmtLoadRunner(JmtLoadOptions options, CheckpointObserver checkpointObserver) {
        this.options = options;
        files = new JmtRunFiles(options.workDir());
        this.checkpointObserver = checkpointObserver;
    }

    public LoadResult run() throws IOException {
        JmtRunFiles.Manifest manifest = files.ensureManifest(options);
        long diskBefore = JmtRunFiles.directoryBytes(files.rocksDbDir());
        long started = System.nanoTime();
        String startedAt = Instant.now().toString();
        long durableCompleted = manifest.completedEntries();
        Long durableVersion = manifest.latestVersion();
        byte[] durableRoot = manifest.rootHex() == null
                ? null : HexFormat.of().parseHex(manifest.rootHex());

        try (HeapSampler heap = new HeapSampler();
             RocksDbJmtStore store = RocksDbJmtStore.open(
                     files.rocksDbDir().toString(), options.storeOptions())) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store, options.pairCacheEntries());
            var latest = store.latestRoot();
            long resumedFrom = latest.map(root -> root.version()).orElse(0L);
            byte[] persistedRoot = latest.map(root -> root.rootHash().clone()).orElse(null);
            validateResume(store, manifest, resumedFrom, persistedRoot);
            durableCompleted = resumedFrom;
            durableVersion = latest.map(root -> root.version()).orElse(null);
            durableRoot = persistedRoot;
            manifest = files.checkpoint(manifest, resumedFrom, durableVersion, persistedRoot,
                    resumedFrom == options.entries() ? "loaded" : "loading");

            long completed = resumedFrom;
            long checkpoints = 0L;
            long lastProgressCompleted = completed;
            long lastProgressNanos = started;
            long nextProgress = options.progressEvery() == 0
                    ? Long.MAX_VALUE
                    : ((completed / options.progressEvery()) + 1) * options.progressEvery();

            while (completed < options.entries()) {
                long batchStart = completed;
                long batchEnd = Math.min(options.entries(), batchStart + options.batchSize());
                Map<byte[], byte[]> updates = new LinkedHashMap<>(
                        (int) Math.min(Integer.MAX_VALUE, (batchEnd - batchStart) * 4 / 3 + 1));
                for (long index = batchStart; index < batchEnd; index++) {
                    updates.put(
                            DeterministicJmtDataset.key(options.seed(), index),
                            DeterministicJmtDataset.value(options.seed(), index));
                }
                byte[] root = tree.put(batchEnd, updates).rootHash();
                completed = batchEnd;
                durableCompleted = completed;
                durableVersion = completed;
                durableRoot = root.clone();
                checkpoints++;
                // Persist the exact durable root before any observer/progress hook can fail. A
                // process death in the narrow commit/sidecar gap is detected on reopen and never
                // silently adopted as this deterministic dataset.
                manifest = files.checkpoint(
                        manifest, completed, completed, root, "loading");
                checkpointObserver.afterCommit(completed, root.clone());

                if (completed >= nextProgress || completed == options.entries()) {
                    long now = System.nanoTime();
                    double elapsed = seconds(started, now);
                    double interval = seconds(lastProgressNanos, now);
                    System.out.printf(
                            "JMT load %,d / %,d (%.2f%%), %.1f entries/s since resume, "
                                    + "%.1f interval, root=%s%n",
                            completed, options.entries(), completed * 100.0 / options.entries(),
                            (completed - resumedFrom) / Math.max(elapsed, 0.001),
                            (completed - lastProgressCompleted) / Math.max(interval, 0.001),
                            shortHex(root));
                    lastProgressCompleted = completed;
                    lastProgressNanos = now;
                    while (nextProgress <= completed
                            && nextProgress < Long.MAX_VALUE - options.progressEvery()) {
                        nextProgress += options.progressEvery();
                    }
                }
            }

            var finalLatest = store.latestRoot().orElseThrow();
            byte[] finalRoot = finalLatest.rootHash();
            manifest = files.checkpoint(
                    manifest, options.entries(), finalLatest.version(), finalRoot, "loaded");
            long ended = System.nanoTime();
            long diskAfter = JmtRunFiles.directoryBytes(files.rocksDbDir());
            var properties = store.sampleDbProperties();
            LoadResult result = new LoadResult(
                    startedAt,
                    Instant.now().toString(),
                    options.entries(),
                    resumedFrom,
                    options.batchSize(),
                    checkpoints,
                    seconds(started, ended),
                    (options.entries() - resumedFrom) / Math.max(seconds(started, ended), 0.001),
                    finalLatest.version(),
                    HexFormat.of().formatHex(finalRoot),
                    diskBefore,
                    diskAfter,
                    heap.peakBytes(),
                    heap.peakRssBytes(),
                    heap.peakRssMinusUsedHeapBytes(),
                    heap.rssSamples(),
                    heap.rssSource(),
                    options.rocksProfile().name().toLowerCase().replace('_', '-'),
                    true,
                    properties.pendingCompactionBytes(),
                    properties.curSizeAllMemTables(),
                    tree.pairCacheStats(),
                    runtimeMetadata());
            files.writeReportSection("load", result, options);
            return result;
        } catch (RuntimeException | IOException error) {
            files.checkpoint(manifest, durableCompleted, durableVersion, durableRoot, "interrupted");
            throw error;
        }
    }

    private void validateResume(
            RocksDbJmtStore store,
            JmtRunFiles.Manifest manifest,
            long resumedFrom,
            byte[] persistedRoot) {
        if (resumedFrom > options.entries()) {
            throw new IllegalStateException("Persisted JMT version " + resumedFrom
                    + " exceeds target entry count " + options.entries());
        }
        if (resumedFrom != options.entries() && resumedFrom % options.batchSize() != 0) {
            throw new IllegalStateException("Persisted JMT version is not a dataset batch boundary: "
                    + resumedFrom);
        }
        if (manifest.completedEntries() > resumedFrom) {
            throw new IllegalStateException("Manifest checkpoint is ahead of durable JMT state");
        }
        if (manifest.completedEntries() < resumedFrom) {
            throw new IllegalStateException("Durable JMT state is ahead of the authenticated "
                    + "dataset manifest; refusing to adopt unverified commits");
        }
        if (manifest.completedEntries() > 0) {
            byte[] recorded = HexFormat.of().parseHex(manifest.rootHex());
            byte[] historical = store.rootHash(manifest.completedEntries()).orElseThrow(
                    () -> new IllegalStateException("Manifest root version is absent from JMT store"));
            if (!java.util.Arrays.equals(recorded, historical)) {
                throw new IllegalStateException("Manifest root does not match durable JMT history");
            }
        }
        if (manifest.completedEntries() == resumedFrom && persistedRoot != null
                && !java.util.Arrays.equals(
                persistedRoot, HexFormat.of().parseHex(manifest.rootHex()))) {
            throw new IllegalStateException("Latest manifest root does not match RocksDB");
        }
    }

    private static Map<String, String> runtimeMetadata() {
        return Map.of(
                "javaVersion", System.getProperty("java.version"),
                "javaVendor", System.getProperty("java.vendor"),
                "vmName", System.getProperty("java.vm.name"),
                "osName", System.getProperty("os.name"),
                "osVersion", System.getProperty("os.version"),
                "osArch", System.getProperty("os.arch"),
                "maxHeapBytes", Long.toString(Runtime.getRuntime().maxMemory()),
                "processors", Integer.toString(Runtime.getRuntime().availableProcessors()));
    }

    private static double seconds(long start, long end) {
        return (end - start) / 1_000_000_000.0;
    }

    private static String shortHex(byte[] value) {
        String hex = HexFormat.of().formatHex(value);
        return hex.substring(0, Math.min(16, hex.length()));
    }

    public record LoadResult(
            String startedAt,
            String completedAt,
            long entries,
            long resumedFrom,
            int batchSize,
            long checkpointsWritten,
            double elapsedSeconds,
            double entriesPerSecond,
            long latestVersion,
            String rootHex,
            long databaseBytesBefore,
            long databaseBytesAfter,
            long peakObservedHeapBytes,
            long peakObservedRssBytes,
            long peakRssMinusUsedHeapBytes,
            long rssSamples,
            String rssSource,
            String rocksDbProfile,
            boolean productionDurabilityOptions,
            long pendingCompactionBytes,
            long currentMemtableBytes,
            com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtCommitmentScheme.PairCacheStats pairCache,
            Map<String, String> runtime) {}

    @FunctionalInterface
    interface CheckpointObserver {
        void afterCommit(long completed, byte[] root);
    }
}
