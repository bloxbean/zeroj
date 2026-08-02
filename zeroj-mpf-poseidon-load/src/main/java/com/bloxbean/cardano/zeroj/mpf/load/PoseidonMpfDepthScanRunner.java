package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.core.api.StorageMode;
import com.bloxbean.cardano.vds.mpf.BenchmarkMpfProofDepthScanner;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbStateTrees;
import com.bloxbean.cardano.vds.rocksdb.namespace.NamespaceOptions;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfCommitmentScheme;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHashFunction;

import java.io.IOException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;

/** Scans every entry under the current RocksDB root without materializing the trie in heap. */
public final class PoseidonMpfDepthScanRunner {
    private final LoadOptions options;
    private final RunFiles files;

    public PoseidonMpfDepthScanRunner(LoadOptions options) {
        this.options = options;
        this.files = new RunFiles(options.workDir());
    }

    public DepthScanResult run() throws IOException {
        files.ensureManifest(options);
        String startedAt = Instant.now().toString();
        long startedNanos = System.nanoTime();

        try (HeapSampler heap = new HeapSampler();
             RocksDbStateTrees state = new RocksDbStateTrees(
                     files.rocksDbDir().toString(), NamespaceOptions.defaults(),
                     StorageMode.MULTI_VERSION, options.rocksDbProfile().config())) {
            long completed = state.rootsIndex().lastVersion();
            if (completed != options.entries()) {
                throw new IllegalStateException("Expected a completed " + options.entries()
                        + " entry database, found checkpoint " + completed);
            }
            long scanVersion = options.depthScanVersion() == -1
                    ? completed
                    : options.depthScanVersion();
            byte[] root = state.rootsIndex().get(scanVersion);
            if (root == null) {
                throw new IllegalStateException("Database has no root checkpoint at version " + scanVersion);
            }

            var scan = BenchmarkMpfProofDepthScanner.scan(
                    state.nodeStore(),
                    PoseidonMpfHashFunction.INSTANCE,
                    new PoseidonMpfCommitmentScheme(PoseidonParamsBLS12_381T3.INSTANCE, 0),
                    root,
                    options.progressEvery(),
                    entries -> System.out.printf("depth scan %,d / %,d (%.2f%%)%n",
                            entries, scanVersion, entries * 100.0 / scanVersion));
            if (scan.entries() != scanVersion) {
                throw new IllegalStateException("Current root contains " + scan.entries()
                        + " entries, expected " + scanVersion);
            }
            if (scan.branchValueEntries() != 0) {
                throw new IllegalStateException("Poseidon MPF profile does not support branch values; found "
                        + scan.branchValueEntries());
            }

            double elapsed = secondsSince(startedNanos);
            DepthScanResult result = new DepthScanResult(
                    startedAt,
                    Instant.now().toString(),
                    scanVersion,
                    HexFormat.of().formatHex(root),
                    scan.branchNodes(),
                    scan.extensionNodes(),
                    scan.visitedNodes(),
                    scan.maxProofSteps(),
                    scan.stepHistogram(),
                    elapsed,
                    scan.visitedNodes() / Math.max(elapsed, 0.001),
                    heap.peakBytes());
            String reportSection = scanVersion == completed ? "depthScan" : "depthScan" + scanVersion;
            files.writeReportSection(reportSection, result);
            System.out.printf("depth scan complete: %,d entries, max=%d steps, %,d nodes in %.3f s%n",
                    result.entries(), result.maxProofSteps(), result.visitedNodes(), result.elapsedSeconds());
            return result;
        }
    }

    private static double secondsSince(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000_000.0;
    }

    public record DepthScanResult(
            String startedAt,
            String completedAt,
            long entries,
            String rootHex,
            long branchNodes,
            long extensionNodes,
            long visitedNodes,
            int maxProofSteps,
            Map<Integer, Long> stepHistogram,
            double elapsedSeconds,
            double nodesPerSecond,
            long peakObservedHeapBytes) {}
}
