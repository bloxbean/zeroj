package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.core.api.StorageMode;
import com.bloxbean.cardano.vds.mpf.MpfTrie;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbStateTrees;
import com.bloxbean.cardano.vds.rocksdb.namespace.NamespaceOptions;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfReference;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfTrie;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfWitness;

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
            MpfTrie trie = PoseidonMpfTrie.create(state.nodeStore(), root);

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
                boolean cclVerified = trie.verifyProofWire(root, key, expectedValue, true, proof);
                boolean referenceVerified = PoseidonMpfReference.including(root, key, expectedValue, proof);
                long verifyNanos = System.nanoTime() - verifyStarted;
                if (!cclVerified || !referenceVerified) {
                    throw new IllegalStateException("Proof verification failed at index " + index
                            + " (CCL=" + cclVerified + ", reference=" + referenceVerified + ")");
                }

                int steps = PoseidonMpfCodec.decode(proof).size();
                long witnessStarted = System.nanoTime();
                PoseidonMpfWitness witness = PoseidonMpfCodec.toWitness(
                        key, proof, Math.max(options.maxSteps(), steps), options.maxForkPrefixChunks());
                long witnessNanos = System.nanoTime() - witnessStarted;

                artifacts.add(new ProofArtifact(index, key, expectedValue, proof, witness, steps));
                metrics.add(new SampleMetric(index, steps, proof.length, proofNanos, verifyNanos, witnessNanos));
                System.out.printf("proof index=%,d steps=%d bytes=%d generate=%.3f ms verify=%.3f ms%n",
                        index, steps, proof.length, proofNanos / 1e6, verifyNanos / 1e6);
            }

            ProofArtifact circuitArtifact = artifacts.stream()
                    .max(java.util.Comparator.comparingInt(ProofArtifact::steps))
                    .orElseThrow();
            ProofResult result = summarize(startedAt, completed, root, metrics, heap.peakBytes(), circuitArtifact.index());
            files.writeReportSection("proofs", result);
            return new ProofRun(result, root.clone(), List.copyOf(artifacts), circuitArtifact);
        }
    }

    private ProofResult summarize(
            String startedAt,
            long completed,
            byte[] root,
            List<SampleMetric> metrics,
            long peakHeap,
            long circuitSampleIndex) {
        List<Long> generation = metrics.stream().map(SampleMetric::generationNanos).toList();
        List<Long> verification = metrics.stream().map(SampleMetric::verificationNanos).toList();
        List<Long> witness = metrics.stream().map(SampleMetric::witnessEncodingNanos).toList();
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
                options.maxForkPrefixChunks(),
                metrics.size(),
                circuitSampleIndex,
                MetricStats.nanos(generation),
                MetricStats.nanos(verification),
                MetricStats.nanos(witness),
                MetricStats.integers(sizes),
                MetricStats.integers(steps),
                Map.copyOf(histogram),
                peakHeap,
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
            PoseidonMpfWitness witness,
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
            long witnessEncodingNanos) {}

    public record ProofResult(
            String startedAt,
            String completedAt,
            long entries,
            String rootHex,
            int maxSteps,
            int maxForkPrefixChunks,
            int sampleCount,
            long circuitSampleIndex,
            Map<String, Double> generationLatency,
            Map<String, Double> verificationLatency,
            Map<String, Double> witnessEncodingLatency,
            Map<String, Double> proofBytes,
            Map<String, Double> proofSteps,
            Map<Integer, Long> stepHistogram,
            long peakObservedHeapBytes,
            List<SampleMetric> samples) {}
}
