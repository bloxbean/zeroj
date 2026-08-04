package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.vds.jmt.commitment.CommitmentScheme;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;

import java.util.Objects;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/** CCL commitment adapter for {@code zeroj-poseidon-jmt-v1}. */
public final class PoseidonJmtCommitmentScheme implements CommitmentScheme {
    public static final int DEFAULT_PAIR_CACHE_ENTRIES = 262_144;
    private final PairHashCache pairHashCache;

    public PoseidonJmtCommitmentScheme() {
        this(DEFAULT_PAIR_CACHE_ENTRIES);
    }

    /** @param pairCacheEntries maximum memoized level-tagged binary pairs; zero disables caching */
    public PoseidonJmtCommitmentScheme(int pairCacheEntries) {
        if (pairCacheEntries < 0) throw new IllegalArgumentException("pairCacheEntries must be >= 0");
        pairHashCache = new PairHashCache(pairCacheEntries);
    }

    public PairCacheStats pairCacheStats() {
        return pairHashCache.stats();
    }

    @Override
    public byte[] commitBranch(NibblePath prefix, byte[][] childHashes) {
        // CCL pre5 creates stored branch commitments with an empty prefix but
        // supplies the traversed prefix to its object verifier. The v1 profile
        // is therefore intentionally prefix-independent; the proof path/key
        // binding is checked separately by CCL and the ZeroJ normalizer.
        Objects.requireNonNull(prefix, "prefix");
        Objects.requireNonNull(childHashes, "childHashes");
        if (childHashes.length != 16) {
            throw new IllegalArgumentException("JMT branch must have exactly 16 child slots");
        }
        byte[][] level = new byte[childHashes.length][];
        for (int index = 0; index < childHashes.length; index++) {
            byte[] child = childHashes[index];
            if (child == null) {
                level[index] = PoseidonJmtCommitments.empty();
            } else {
                com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash.decode(child);
                level[index] = child.clone();
            }
        }
        for (int depth = 0; depth < 4; depth++) {
            byte[][] next = new byte[level.length / 2][];
            for (int index = 0; index < level.length; index += 2) {
                next[index / 2] = pairHashCache.digest(depth, level[index], level[index + 1]);
            }
            level = next;
        }
        return level[0];
    }

    @Override
    public byte[] commitLeaf(byte[] keyHash, byte[] valueHash) {
        return PoseidonJmtCommitments.leaf(keyHash, valueHash);
    }

    @Override
    public byte[] nullHash() {
        return PoseidonJmtCommitments.empty();
    }

    public record PairCacheStats(int capacity, int size, long hits, long misses) {}

    private static final class PairHashCache {
        private final int capacity;
        private final Map<PairKey, byte[]> entries;
        private long hits;
        private long misses;

        private PairHashCache(int capacity) {
            this.capacity = capacity;
            entries = capacity == 0 ? Map.of() : new LinkedHashMap<>(1024, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<PairKey, byte[]> eldest) {
                    return size() > PairHashCache.this.capacity;
                }
            };
        }

        private synchronized byte[] digest(int level, byte[] left, byte[] right) {
            if (capacity == 0) return PoseidonJmtCommitments.binaryPair(level, left, right);
            PairKey key = new PairKey(level, left, right);
            byte[] cached = entries.get(key);
            if (cached != null) {
                hits++;
                return cached.clone();
            }
            misses++;
            byte[] digest = PoseidonJmtCommitments.binaryPair(level, left, right);
            entries.put(key, digest.clone());
            return digest;
        }

        private synchronized PairCacheStats stats() {
            return new PairCacheStats(capacity, entries.size(), hits, misses);
        }
    }

    private static final class PairKey {
        private final byte[] value;
        private final int hashCode;

        private PairKey(int level, byte[] left, byte[] right) {
            value = new byte[1 + left.length + right.length];
            value[0] = (byte) level;
            System.arraycopy(left, 0, value, 1, left.length);
            System.arraycopy(right, 0, value, 1 + left.length, right.length);
            hashCode = Arrays.hashCode(value);
        }

        @Override public boolean equals(Object other) {
            return this == other || other instanceof PairKey key && Arrays.equals(value, key.value);
        }

        @Override public int hashCode() { return hashCode; }
    }
}
