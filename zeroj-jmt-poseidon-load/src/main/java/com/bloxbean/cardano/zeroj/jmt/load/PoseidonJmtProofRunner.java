package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness.PoseidonJmtInclusionWitness;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class PoseidonJmtProofRunner {
    private final JmtLoadOptions options;
    private final JmtRunFiles files;

    public PoseidonJmtProofRunner(JmtLoadOptions options) {
        this.options = options;
        files = new JmtRunFiles(options.workDir());
    }

    public ProofRun run() throws IOException {
        JmtRunFiles.Manifest manifest = files.ensureManifest(options);
        if (manifest.completedEntries() != options.entries()) {
            throw new IllegalStateException("JMT load is incomplete: "
                    + manifest.completedEntries() + " / " + options.entries());
        }
        long reopenStarted = System.nanoTime();
        try (HeapSampler heap = new HeapSampler();
             RocksDbJmtStore store = RocksDbJmtStore.open(
                     files.rocksDbDir().toString(), options.storeOptions())) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            double reopenSeconds = elapsed(reopenStarted);
            var latest = store.latestRoot().orElseThrow();
            byte[] root = latest.rootHash();
            if (latest.version() != options.entries()
                    || !HexFormat.of().formatHex(root).equals(manifest.rootHex())) {
                throw new IllegalStateException("JMT manifest/latest-root mismatch");
            }

            List<ProofArtifact> artifacts = new ArrayList<>();
            Map<Integer, Long> depthHistogram = new TreeMap<>();
            List<Long> wireBytes = new ArrayList<>();
            List<Long> proofNanos = new ArrayList<>();
            List<Long> verificationNanos = new ArrayList<>();
            List<Long> verifiedWitnessNormalizationNanos = new ArrayList<>();
            for (int sample = 0; sample < options.samples(); sample++) {
                long index = sampleIndex(sample, options.samples(), options.entries());
                byte[] key = DeterministicJmtDataset.key(options.seed(), index);
                byte[] value = DeterministicJmtDataset.value(options.seed(), index);
                long proofStarted = System.nanoTime();
                JmtProof proof = tree.getProof(key, latest.version()).orElseThrow();
                byte[] wire = tree.encodeProof(key, proof);
                long proofElapsed = System.nanoTime() - proofStarted;
                long verificationStarted = System.nanoTime();
                if (!tree.verifyInclusionProof(root, key, value, proof)
                        || !tree.verifyProofWire(root, key, value, true, wire)) {
                    throw new IllegalStateException("Generated JMT proof failed strict verification");
                }
                long verificationElapsed = System.nanoTime() - verificationStarted;
                long verifiedNormalizationStarted = System.nanoTime();
                PoseidonJmtInclusionWitness witness = PoseidonJmtInclusionWitness.create(
                        root, key, value, proof, options.maxLevels());
                long verifiedNormalizationElapsed = System.nanoTime() - verifiedNormalizationStarted;
                artifacts.add(new ProofArtifact(
                        index, key, value, proof, wire, witness,
                        proof.steps().size(), proofElapsed, verificationElapsed,
                        verifiedNormalizationElapsed));
                depthHistogram.merge(proof.steps().size(), 1L, Long::sum);
                wireBytes.add((long) wire.length);
                proofNanos.add(proofElapsed);
                verificationNanos.add(verificationElapsed);
                verifiedWitnessNormalizationNanos.add(verifiedNormalizationElapsed);
                System.out.printf("JMT proof index=%,d levels=%d bytes=%d generate=%.3f ms "
                                + "verify=%.3f ms verified-normalize=%.3f ms%n",
                        index, proof.steps().size(), wire.length, proofElapsed / 1e6,
                        verificationElapsed / 1e6, verifiedNormalizationElapsed / 1e6);
            }
            ProofResult result = new ProofResult(
                    Instant.now().toString(),
                    latest.version(),
                    options.samples(),
                    Map.copyOf(depthHistogram),
                    depthHistogram.keySet().stream().mapToInt(Integer::intValue).max().orElse(0),
                    Stats.of(wireBytes),
                    Stats.of(proofNanos),
                    Stats.of(verificationNanos),
                    Stats.of(verifiedWitnessNormalizationNanos),
                    reopenSeconds,
                    heap.peakBytes(),
                    heap.peakRssBytes(),
                    heap.peakRssMinusUsedHeapBytes(),
                    heap.rssSamples(),
                    heap.rssSource(),
                    options.maxLevels(),
                    options.pairCacheEntries());
            files.writeReportSection("proofs", result, options);
            return new ProofRun(root, List.copyOf(artifacts), result);
        }
    }

    private static long sampleIndex(int sample, int samples, long entries) {
        if (samples == 1) return entries / 2;
        return Math.min(entries - 1, Math.multiplyExact((long) sample, entries - 1) / (samples - 1));
    }

    private static double elapsed(long start) {
        return (System.nanoTime() - start) / 1_000_000_000.0;
    }

    public record ProofArtifact(
            long index,
            byte[] key,
            byte[] value,
            JmtProof proof,
            byte[] wire,
            PoseidonJmtInclusionWitness witness,
            int levels,
            long proofGenerationNanos,
            long proofVerificationNanos,
            long verifiedWitnessNormalizationNanos) {
        public ProofArtifact {
            key = key.clone();
            value = value.clone();
            wire = wire.clone();
        }
        @Override public byte[] key() { return key.clone(); }
        @Override public byte[] value() { return value.clone(); }
        @Override public byte[] wire() { return wire.clone(); }
    }

    public record ProofRun(byte[] root, List<ProofArtifact> artifacts, ProofResult result) {
        public ProofRun {
            root = root.clone();
            artifacts = List.copyOf(artifacts);
        }
        @Override public byte[] root() { return root.clone(); }
    }

    public record ProofResult(
            String completedAt,
            long version,
            int samples,
            Map<Integer, Long> depthHistogram,
            int maxObservedLevels,
            Stats nativeWireBytes,
            Stats proofGenerationNanos,
            Stats proofVerificationNanos,
            Stats verifiedWitnessNormalizationNanos,
            double reopenSeconds,
            long peakObservedHeapBytes,
            long peakObservedRssBytes,
            long peakRssMinusUsedHeapBytes,
            long rssSamples,
            String rssSource,
            int configuredMaxLevels,
            int configuredPairCacheEntries) {}

    public record Stats(long minimum, long median, long p95, long maximum, double average) {
        static Stats of(List<Long> values) {
            if (values.isEmpty()) return new Stats(0, 0, 0, 0, 0);
            long[] sorted = values.stream().mapToLong(Long::longValue).sorted().toArray();
            return new Stats(
                    sorted[0],
                    percentile(sorted, 0.50),
                    percentile(sorted, 0.95),
                    sorted[sorted.length - 1],
                    java.util.Arrays.stream(sorted).average().orElse(0));
        }
        private static long percentile(long[] values, double percentile) {
            int index = (int) Math.ceil(percentile * values.length) - 1;
            return values[Math.max(0, Math.min(values.length - 1, index))];
        }
    }
}
