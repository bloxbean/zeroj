package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.core.api.StorageMode;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbStateTrees;
import com.bloxbean.cardano.vds.rocksdb.namespace.NamespaceOptions;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness.PoseidonMpfBranchWitness;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfReference;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.TreeMap;
import java.util.TreeSet;

public final class PoseidonMpfProofRunner {
    private final LoadOptions options;
    private final RunFiles files;

    public PoseidonMpfProofRunner(LoadOptions options) {
        this.options = options;
        this.files = new RunFiles(options.workDir());
    }

    public ProofRun run() throws IOException {
        files.ensureManifest(options);
        List<ProofArtifact> artifacts = new ArrayList<>();
        List<SampleMetric> metrics = new ArrayList<>();
        byte[] root;
        long completed;
        String startedAt = Instant.now().toString();

        try (HeapSampler heap = new HeapSampler();
             RocksDbStateTrees state = new RocksDbStateTrees(
                     files.rocksDbDir().toString(), NamespaceOptions.defaults(),
                     StorageMode.MULTI_VERSION, options.rocksDbProfile().config())) {
            completed = state.rootsIndex().lastVersion();
            if (completed != options.entries()) {
                throw new IllegalStateException("Expected a completed " + options.entries()
                        + " entry database, found checkpoint " + completed);
            }
            root = state.rootsIndex().latest();
            if (root == null) throw new IllegalStateException("Completed database has no root");
            PoseidonMpfTrie trie = PoseidonMpfTrie.create(state.nodeStore(), root);

            for (long index : sampleIndices(options.entries(), options.samples(), options.seed())) {
                byte[] key = DeterministicDataset.key(options.seed(), index);
                byte[] expectedValue = DeterministicDataset.value(options.seed(), index);
                byte[] storedValue = trie.get(key);
                if (!Arrays.equals(expectedValue, storedValue)) {
                    throw new IllegalStateException("Stored value mismatch at dataset index " + index);
                }

                long proofStarted = System.nanoTime();
                byte[] proof = trie.getProofWire(key).orElseThrow(() ->
                        new IllegalStateException("Missing inclusion proof at index " + index));
                long proofNanos = System.nanoTime() - proofStarted;

                long verifyStarted = System.nanoTime();
                boolean strictProfileVerified = PoseidonMpfReference.including(
                        root, key, expectedValue, proof);
                long verifyNanos = System.nanoTime() - verifyStarted;
                if (!strictProfileVerified) {
                    throw new IllegalStateException(
                            "Strict MPF v1 proof verification failed at index " + index);
                }

                int steps = PoseidonMpfCodec.decode(proof).size();
                long witnessStarted = System.nanoTime();
                PoseidonMpfBranchWitness witness = PoseidonMpfBranchWitness.inclusion(
                        root, key, expectedValue, proof, Math.max(options.maxSteps(), steps));
                long verifiedNormalizationNanos = System.nanoTime() - witnessStarted;

                artifacts.add(new ProofArtifact(index, key, expectedValue, proof, witness, steps));
                metrics.add(new SampleMetric(
                        index, steps, proof.length, proofNanos, verifyNanos,
                        verifiedNormalizationNanos));
                System.out.printf("proof index=%,d steps=%d bytes=%d generate=%.3f ms "
                                + "verify=%.3f ms verified-normalize=%.3f ms%n",
                        index, steps, proof.length, proofNanos / 1e6, verifyNanos / 1e6,
                        verifiedNormalizationNanos / 1e6);
            }

            ProofArtifact circuitArtifact = artifacts.stream()
                    .max(java.util.Comparator.comparingInt(ProofArtifact::steps))
                    .orElseThrow();
            ProofResult result = summarize(
                    startedAt, completed, root, metrics,
                    heap.peakBytes(), heap.peakRssBytes(),
                    heap.peakRssMinusUsedHeapBytes(), heap.rssSamples(), heap.rssSource(),
                    circuitArtifact.index());
            files.writeReportSection("proofs", result, options);
            return new ProofRun(result, root.clone(), List.copyOf(artifacts), circuitArtifact);
        }
    }

    private ProofResult summarize(
            String startedAt,
            long completed,
            byte[] root,
            List<SampleMetric> metrics,
            long peakHeap,
            long peakRss,
            long peakRssMinusUsedHeap,
            long rssSamples,
            String rssSource,
            long circuitSampleIndex) {
        List<Long> generation = metrics.stream().map(SampleMetric::generationNanos).toList();
        List<Long> verification = metrics.stream().map(SampleMetric::verificationNanos).toList();
        List<Long> witness = metrics.stream()
                .map(SampleMetric::verifiedWitnessNormalizationNanos).toList();
        List<Integer> sizes = metrics.stream().map(SampleMetric::proofBytes).toList();
        List<Integer> steps = metrics.stream().map(SampleMetric::steps).toList();
        Map<Integer, Long> histogram = new TreeMap<>();
        for (int step : steps) histogram.merge(step, 1L, Long::sum);
        return new ProofResult(
                startedAt,
                Instant.now().toString(),
                completed,
                HexFormat.of().formatHex(root),
                options.maxSteps(),
                metrics.size(),
                circuitSampleIndex,
                MetricStats.nanos(generation),
                MetricStats.nanos(verification),
                MetricStats.nanos(witness),
                MetricStats.integers(sizes),
                MetricStats.integers(steps),
                Map.copyOf(histogram),
                peakHeap,
                peakRss,
                peakRssMinusUsedHeap,
                rssSamples,
                rssSource,
                List.copyOf(metrics));
    }

    static List<Long> sampleIndices(long entries, int requested, long seed) {
        int desired = (int) Math.min(entries, requested);
        TreeSet<Long> indices = new TreeSet<>();
        long[] boundaries = {0L, entries / 4, entries / 2, (entries * 3) / 4, entries - 1};
        for (long boundary : boundaries) {
            if (indices.size() == desired) break;
            indices.add(boundary);
        }
        Random random = new Random(seed ^ 0x5a4d5046L);
        while (indices.size() < desired) indices.add(random.nextLong(entries));
        return List.copyOf(indices);
    }

    public record ProofRun(
            ProofResult result,
            byte[] root,
            List<ProofArtifact> artifacts,
            ProofArtifact circuitArtifact) {
        public ProofRun {
            root = root.clone();
            artifacts = List.copyOf(artifacts);
        }
        @Override public byte[] root() { return root.clone(); }
    }

    public record ProofArtifact(
            long index,
            byte[] key,
            byte[] value,
            byte[] proof,
            PoseidonMpfBranchWitness witness,
            int steps) {
        public ProofArtifact {
            key = key.clone();
            value = value.clone();
            proof = proof.clone();
        }
        @Override public byte[] key() { return key.clone(); }
        @Override public byte[] value() { return value.clone(); }
        @Override public byte[] proof() { return proof.clone(); }
    }

    public record SampleMetric(
            long index,
            int steps,
            int proofBytes,
            long generationNanos,
            long verificationNanos,
            long verifiedWitnessNormalizationNanos) {}

    public record ProofResult(
            String startedAt,
            String completedAt,
            long entries,
            String rootHex,
            int maxSteps,
            int sampleCount,
            long circuitSampleIndex,
            Map<String, Double> generationLatency,
            Map<String, Double> verificationLatency,
            /** Includes the witness factory's mandatory second strict proof verification. */
            Map<String, Double> verifiedWitnessNormalizationLatency,
            Map<String, Double> proofBytes,
            Map<String, Double> proofSteps,
            Map<Integer, Long> stepHistogram,
            long peakObservedHeapBytes,
            long peakObservedRssBytes,
            long peakRssMinusUsedHeapBytes,
            long rssSamples,
            String rssSource,
            List<SampleMetric> samples) {}
}
