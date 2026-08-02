package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.core.api.StorageMode;
import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbStateTrees;
import com.bloxbean.cardano.vds.rocksdb.namespace.NamespaceOptions;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfCommitmentScheme;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHashFunction;
import org.rocksdb.WriteBatch;
import org.rocksdb.WriteOptions;

import java.io.IOException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

public final class PoseidonMpfLoadRunner {
    private final LoadOptions options;
    private final RunFiles files;
    private final CheckpointObserver checkpointObserver;

    public PoseidonMpfLoadRunner(LoadOptions options) {
        this(options, (completed, root) -> {});
    }

    PoseidonMpfLoadRunner(LoadOptions options, CheckpointObserver checkpointObserver) {
        this.options = options;
        this.files = new RunFiles(options.workDir());
        this.checkpointObserver = checkpointObserver;
    }

    public LoadResult run() throws IOException {
        RunFiles.Manifest manifest = files.ensureManifest(options);
        long diskBefore = RunFiles.directoryBytes(files.rocksDbDir());
        long startedNanos = System.nanoTime();
        String startedAt = Instant.now().toString();
        long resumedFrom;
        long checkpoints = 0L;
        byte[] finalRoot;
        long durableCompleted = manifest.completedEntries();
        byte[] durableRoot = manifest.rootHex() == null
                ? null
                : HexFormat.of().parseHex(manifest.rootHex());

        try (HeapSampler heap = new HeapSampler();
             RocksDbStateTrees state = new RocksDbStateTrees(
                     files.rocksDbDir().toString(), NamespaceOptions.defaults(),
                     StorageMode.MULTI_VERSION, options.rocksDbProfile().config())) {
            long lastVersion = state.rootsIndex().lastVersion();
            resumedFrom = lastVersion < 0 ? 0L : lastVersion;
            byte[] persistedRoot = lastVersion < 0 ? null : state.rootsIndex().latest();
            durableCompleted = resumedFrom;
            durableRoot = persistedRoot;
            if (resumedFrom > options.entries()) {
                throw new IllegalStateException("Persisted checkpoint " + resumedFrom
                        + " exceeds requested entries " + options.entries());
            }
            manifest = files.checkpoint(manifest, resumedFrom, persistedRoot,
                    resumedFrom == options.entries() ? "loaded" : "loading");

            PoseidonMpfCommitmentScheme commitments = new PoseidonMpfCommitmentScheme(
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    options.pairCacheEntries());
            MpfTrie trie = new MpfTrie(
                    state.nodeStore(),
                    new PoseidonMpfHashFunction(PoseidonParamsBLS12_381T3.INSTANCE),
                    persistedRoot,
                    commitments);
            long completed = resumedFrom;
            long lastProgressCompleted = completed;
            long lastProgressNanos = startedNanos;
            long nextProgress = options.progressEvery() == 0
                    ? Long.MAX_VALUE
                    : ((completed / options.progressEvery()) + 1) * options.progressEvery();

            while (completed < options.entries()) {
                long batchStart = completed;
                long batchEnd = Math.min(options.entries(), batchStart + options.batchSize());
                try (WriteBatch batch = new WriteBatch(); WriteOptions writeOptions = new WriteOptions()) {
                    writeOptions.setDisableWAL(!options.wal());
                    state.nodeStore().withBatch(batch, () -> {
                        for (long index = batchStart; index < batchEnd; index++) {
                            trie.put(
                                    DeterministicDataset.key(options.seed(), index),
                                    DeterministicDataset.value(options.seed(), index));
                        }
                        return null;
                    });
                    byte[] rootAtCheckpoint = trie.getRootHash();
                    state.rootsIndex().withBatch(batch, () -> {
                        state.rootsIndex().put(batchEnd, rootAtCheckpoint);
                        return null;
                    });
                    state.db().write(writeOptions, batch);
                } catch (Exception e) {
                    throw new IllegalStateException("Failed to commit entries [" + batchStart
                            + ", " + batchEnd + ")", e);
                }
                completed = batchEnd;
                durableCompleted = completed;
                durableRoot = trie.getRootHash();
                checkpoints++;
                checkpointObserver.afterCommit(completed, durableRoot.clone());
                if (completed >= nextProgress || completed == options.entries()) {
                    double elapsed = secondsSince(startedNanos);
                    long progressNanos = System.nanoTime();
                    double intervalSeconds = (progressNanos - lastProgressNanos) / 1_000_000_000.0;
                    double intervalRate = (completed - lastProgressCompleted)
                            / Math.max(intervalSeconds, 0.001);
                    System.out.printf("load %,d / %,d (%.2f%%), %.1f entries/s since resume, "
                                    + "%.1f interval, root=%s%n",
                            completed, options.entries(), completed * 100.0 / options.entries(),
                            (completed - resumedFrom) / Math.max(elapsed, 0.001),
                            intervalRate,
                            shortHex(trie.getRootHash()));
                    lastProgressCompleted = completed;
                    lastProgressNanos = progressNanos;
                    while (nextProgress <= completed && nextProgress < Long.MAX_VALUE - options.progressEvery()) {
                        nextProgress += options.progressEvery();
                    }
                }
            }
            finalRoot = trie.getRootHash();
            manifest = files.checkpoint(manifest, options.entries(), finalRoot, "loaded");

            double elapsedSeconds = secondsSince(startedNanos);
            long diskAfter = RunFiles.directoryBytes(files.rocksDbDir());
            LoadResult result = new LoadResult(
                    startedAt,
                    Instant.now().toString(),
                    options.entries(),
                    resumedFrom,
                    options.batchSize(),
                    checkpoints,
                    elapsedSeconds,
                    (options.entries() - resumedFrom) / Math.max(elapsedSeconds, 0.001),
                    options.wal(),
                    options.rocksDbProfile().name().toLowerCase().replace('_', '-'),
                    HexFormat.of().formatHex(finalRoot),
                    diskBefore,
                    diskAfter,
                    heap.peakBytes(),
                    commitments.pairCacheStats(),
                    runtimeMetadata());
            files.writeReportSection("load", result);
            return result;
        } catch (RuntimeException | IOException e) {
            files.checkpoint(manifest, durableCompleted, durableRoot, "interrupted");
            throw e;
        }
    }

    private static Map<String, String> runtimeMetadata() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("javaVersion", System.getProperty("java.version"));
        values.put("javaVendor", System.getProperty("java.vendor"));
        values.put("vmName", System.getProperty("java.vm.name"));
        values.put("osName", System.getProperty("os.name"));
        values.put("osVersion", System.getProperty("os.version"));
        values.put("osArch", System.getProperty("os.arch"));
        values.put("maxHeapBytes", Long.toString(Runtime.getRuntime().maxMemory()));
        values.put("processors", Integer.toString(Runtime.getRuntime().availableProcessors()));
        return Map.copyOf(values);
    }

    private static double secondsSince(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000_000.0;
    }

    private static String shortHex(byte[] bytes) {
        if (bytes == null) return "null";
        String hex = HexFormat.of().formatHex(bytes);
        return hex.substring(0, Math.min(hex.length(), 16));
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
            boolean walEnabled,
            String rocksDbProfile,
            String rootHex,
            long databaseBytesBefore,
            long databaseBytesAfter,
            long peakObservedHeapBytes,
            PoseidonMpfCommitmentScheme.PairCacheStats pairCache,
            Map<String, String> runtime) {}

    @FunctionalInterface
    interface CheckpointObserver {
        void afterCommit(long completed, byte[] root);
    }
}
