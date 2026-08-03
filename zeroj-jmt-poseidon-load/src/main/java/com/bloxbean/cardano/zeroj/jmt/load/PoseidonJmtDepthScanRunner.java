package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtHashFunction;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;

import java.io.IOException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

/** Exact all-key inclusion-proof depth census for the authenticated benchmark dataset. */
public final class PoseidonJmtDepthScanRunner {
    static final String METHOD = "all-key-hash-nearest-neighbor-lcp-v1";
    private static final int HASH_BYTES = 32;
    private static final int INSERTION_SORT_THRESHOLD = 24;

    private final JmtLoadOptions options;
    private final JmtRunFiles files;

    public PoseidonJmtDepthScanRunner(JmtLoadOptions options) {
        this.options = options;
        files = new JmtRunFiles(options.workDir());
    }

    public DepthScanResult run() throws IOException {
        JmtRunFiles.Manifest manifest = files.ensureManifest(options);
        if (manifest.completedEntries() != options.entries()) {
            throw new IllegalStateException("JMT load is incomplete: "
                    + manifest.completedEntries() + " / " + options.entries());
        }
        validateStoredHead(manifest);
        if (options.entries() > Integer.MAX_VALUE / HASH_BYTES) {
            throw new IllegalArgumentException("depth scan supports at most "
                    + (Integer.MAX_VALUE / HASH_BYTES) + " entries per JVM invocation");
        }

        int entries = Math.toIntExact(options.entries());
        String startedAt = Instant.now().toString();
        long started = System.nanoTime();
        try (HeapSampler resources = new HeapSampler()) {
            byte[] hashes = new byte[Math.multiplyExact(entries, HASH_BYTES)];
            PoseidonJmtHashFunction hashFunction = new PoseidonJmtHashFunction();
            long hashStarted = System.nanoTime();
            long nextProgress = options.progressEvery() == 0
                    ? Long.MAX_VALUE : options.progressEvery();
            for (int index = 0; index < entries; index++) {
                byte[] hash = hashFunction.digest(DeterministicJmtDataset.key(options.seed(), index));
                if (hash.length != HASH_BYTES) {
                    throw new IllegalStateException("JMT key hash width drift: " + hash.length);
                }
                System.arraycopy(hash, 0, hashes, index * HASH_BYTES, HASH_BYTES);
                long completed = (long) index + 1;
                if (completed >= nextProgress || completed == entries) {
                    System.out.printf("JMT depth scan hashed %,d / %,d (%.2f%%)%n",
                            completed, entries, completed * 100.0 / entries);
                    while (nextProgress <= completed
                            && nextProgress < Long.MAX_VALUE - options.progressEvery()) {
                        nextProgress += options.progressEvery();
                    }
                }
            }
            double hashSeconds = elapsed(hashStarted);

            long sortStarted = System.nanoTime();
            sort(hashes, entries);
            double sortSeconds = elapsed(sortStarted);

            long histogramStarted = System.nanoTime();
            Map<Integer, Long> histogram = depthHistogram(hashes, entries);
            double histogramSeconds = elapsed(histogramStarted);
            int maximum = histogram.keySet().stream().mapToInt(Integer::intValue).max().orElse(0);
            DepthScanResult result = new DepthScanResult(
                    startedAt,
                    Instant.now().toString(),
                    METHOD,
                    true,
                    options.entries(),
                    manifest.latestVersion() == null ? -1L : manifest.latestVersion(),
                    Map.copyOf(histogram),
                    maximum,
                    hashSeconds,
                    sortSeconds,
                    histogramSeconds,
                    elapsed(started),
                    hashes.length,
                    resources.peakBytes(),
                    resources.peakRssBytes(),
                    resources.peakRssMinusUsedHeapBytes(),
                    resources.rssSamples(),
                    resources.rssSource());
            files.writeReportSection("depth-scan", result, options);
            System.out.printf("JMT exact depth scan complete: %,d leaves, max=%d, histogram=%s, "
                            + "hash=%.3f s sort=%.3f s total=%.3f s%n",
                    entries, maximum, histogram, hashSeconds, sortSeconds, result.elapsedSeconds());
            return result;
        }
    }

    private void validateStoredHead(JmtRunFiles.Manifest manifest) {
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                files.rocksDbDir().toString(), options.storeOptions())) {
            // Constructing the profile facade also fails closed on a foreign on-disk format.
            new PoseidonJmtTree(store, 0);
            var latest = store.latestRoot().orElseThrow(
                    () -> new IllegalStateException("JMT has no persisted root"));
            if (latest.version() != options.entries()
                    || manifest.latestVersion() == null
                    || latest.version() != manifest.latestVersion()
                    || !HexFormat.of().formatHex(latest.rootHash()).equals(manifest.rootHex())) {
                throw new IllegalStateException("JMT manifest/latest-root mismatch");
            }
        }
    }

    /**
     * A compressed radix-16 JMT stores a leaf at one nibble beyond its longest common prefix
     * with any other key hash. In lexicographic order that maximum is attained by one of the
     * leaf's two immediate neighbors, so this produces the exact proof-step histogram without
     * materializing five million proof objects.
     */
    static Map<Integer, Long> depthHistogram(byte[] sortedHashes, int entries) {
        if (sortedHashes.length != Math.multiplyExact(entries, HASH_BYTES)) {
            throw new IllegalArgumentException("hash buffer length does not match entry count");
        }
        Map<Integer, Long> histogram = new TreeMap<>();
        if (entries == 0) return histogram;
        if (entries == 1) {
            histogram.put(0, 1L);
            return histogram;
        }
        int leftCommonPrefix = 0;
        for (int index = 1; index < entries; index++) {
            int rightCommonPrefix = commonPrefixNibbles(
                    sortedHashes, (index - 1) * HASH_BYTES, index * HASH_BYTES);
            if (rightCommonPrefix == HASH_BYTES * 2) {
                throw new IllegalStateException("Duplicate 256-bit JMT key hash at sorted index "
                        + index);
            }
            histogram.merge(Math.max(leftCommonPrefix, rightCommonPrefix) + 1, 1L, Long::sum);
            leftCommonPrefix = rightCommonPrefix;
        }
        histogram.merge(leftCommonPrefix + 1, 1L, Long::sum);
        return histogram;
    }

    private static int commonPrefixNibbles(byte[] values, int left, int right) {
        int common = 0;
        for (int index = 0; index < HASH_BYTES; index++) {
            int a = values[left + index] & 0xff;
            int b = values[right + index] & 0xff;
            if (a == b) {
                common += 2;
                continue;
            }
            if ((a >>> 4) == (b >>> 4)) common++;
            return common;
        }
        return common;
    }

    static void sort(byte[] hashes, int entries) {
        if (hashes.length != Math.multiplyExact(entries, HASH_BYTES)) {
            throw new IllegalArgumentException("hash buffer length does not match entry count");
        }
        radixSort(hashes, 0, entries, 0);
    }

    private static void radixSort(byte[] values, int from, int to, int byteIndex) {
        int size = to - from;
        if (size < 2 || byteIndex == HASH_BYTES) return;
        if (size <= INSERTION_SORT_THRESHOLD) {
            insertionSort(values, from, to, byteIndex);
            return;
        }

        int[] counts = new int[256];
        for (int record = from; record < to; record++) {
            counts[values[record * HASH_BYTES + byteIndex] & 0xff]++;
        }
        int[] starts = new int[256];
        int cursor = from;
        for (int bucket = 0; bucket < counts.length; bucket++) {
            starts[bucket] = cursor;
            cursor += counts[bucket];
        }
        int[] next = starts.clone();
        for (int bucket = 0; bucket < counts.length; bucket++) {
            int end = starts[bucket] + counts[bucket];
            while (next[bucket] < end) {
                int record = next[bucket];
                int destinationBucket = values[record * HASH_BYTES + byteIndex] & 0xff;
                if (destinationBucket == bucket) {
                    next[bucket]++;
                } else {
                    swap(values, record, next[destinationBucket]++);
                }
            }
        }
        for (int bucket = 0; bucket < counts.length; bucket++) {
            int begin = starts[bucket];
            int end = begin + counts[bucket];
            if (end - begin > 1) radixSort(values, begin, end, byteIndex + 1);
        }
    }

    private static void insertionSort(byte[] values, int from, int to, int byteIndex) {
        byte[] value = new byte[HASH_BYTES];
        for (int record = from + 1; record < to; record++) {
            System.arraycopy(values, record * HASH_BYTES, value, 0, HASH_BYTES);
            int position = record;
            while (position > from
                    && compare(values, (position - 1) * HASH_BYTES, value, byteIndex) > 0) {
                System.arraycopy(values, (position - 1) * HASH_BYTES,
                        values, position * HASH_BYTES, HASH_BYTES);
                position--;
            }
            System.arraycopy(value, 0, values, position * HASH_BYTES, HASH_BYTES);
        }
    }

    private static int compare(byte[] values, int leftOffset, byte[] right, int byteIndex) {
        for (int index = byteIndex; index < HASH_BYTES; index++) {
            int comparison = Integer.compare(values[leftOffset + index] & 0xff, right[index] & 0xff);
            if (comparison != 0) return comparison;
        }
        return 0;
    }

    private static void swap(byte[] values, int leftRecord, int rightRecord) {
        if (leftRecord == rightRecord) return;
        int left = leftRecord * HASH_BYTES;
        int right = rightRecord * HASH_BYTES;
        for (int index = 0; index < HASH_BYTES; index++) {
            byte temporary = values[left + index];
            values[left + index] = values[right + index];
            values[right + index] = temporary;
        }
    }

    private static double elapsed(long started) {
        return (System.nanoTime() - started) / 1_000_000_000.0;
    }

    public record DepthScanResult(
            String startedAt,
            String completedAt,
            String method,
            boolean exactForManifestDataset,
            long entries,
            long version,
            Map<Integer, Long> depthHistogram,
            int maxProofLevels,
            double hashSeconds,
            double sortSeconds,
            double histogramSeconds,
            double elapsedSeconds,
            long hashBufferBytes,
            long peakObservedHeapBytes,
            long peakObservedRssBytes,
            long peakRssMinusUsedHeapBytes,
            long rssSamples,
            String rssSource) {}
}
