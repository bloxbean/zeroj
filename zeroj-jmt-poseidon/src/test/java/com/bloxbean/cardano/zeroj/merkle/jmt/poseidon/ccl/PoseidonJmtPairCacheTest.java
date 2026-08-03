package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PoseidonJmtPairCacheTest {
    @Test
    void boundedPairCachePreservesCommitmentsAndRecordsReuse() {
        byte[][] children = new byte[16][];
        children[3] = PoseidonJmtHash.digest(new byte[]{1});
        children[12] = PoseidonJmtHash.digest(new byte[]{2});
        byte[] expected = PoseidonJmtCommitments.branch(children);

        var cached = new PoseidonJmtCommitmentScheme(32);
        var uncached = new PoseidonJmtCommitmentScheme(0);
        for (int repetition = 0; repetition < 20; repetition++) {
            assertArrayEquals(expected, cached.commitBranch(NibblePath.EMPTY, children));
            assertArrayEquals(expected, uncached.commitBranch(NibblePath.EMPTY, children));
        }

        var stats = cached.pairCacheStats();
        assertEquals(32, stats.capacity());
        assertTrue(stats.size() <= stats.capacity());
        assertTrue(stats.hits() > stats.misses());
        assertEquals(0, uncached.pairCacheStats().size());
    }
}
