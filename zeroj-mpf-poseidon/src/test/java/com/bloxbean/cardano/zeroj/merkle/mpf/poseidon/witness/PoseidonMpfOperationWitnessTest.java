package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness;

import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonMpfOperationWitnessTest {

    @Test
    void normalizesInclusionAndCanonicalZeroPadding() {
        PoseidonMpfTrie trie = populated();
        byte[] key = bytes("member-1");
        byte[] value = bytes("active");
        byte[] wire = trie.getProofWire(key).orElseThrow();
        int branches = PoseidonMpfCodec.decode(wire).size();

        var witness = PoseidonMpfBranchWitness.inclusion(
                trie.getRootHash(), key, value, wire, branches + 2);

        assertEquals(branches, witness.branchCount());
        assertEquals(branches + 2, witness.maxBranches());
        assertEquals(64, witness.keyPath().size());
        for (int index = branches; index < witness.maxBranches(); index++) {
            assertEquals(0, witness.skip().get(index).signum());
            assertEquals(0, witness.valid().get(index).signum());
            assertTrue(witness.siblings().get(index).stream().allMatch(valueAtIndex -> valueAtIndex.signum() == 0));
        }
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfBranchWitness.inclusion(
                trie.getRootHash(), key, bytes("wrong"), wire, branches));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfBranchWitness.inclusion(
                trie.getRootHash(), key, value, wire, Math.max(0, branches - 1)));
    }

    @Test
    void keepsEmptyAndDifferentLeafProofLanguagesSeparate() {
        PoseidonMpfTrie trie = populated();
        byte[] emptyQuery = findProofOfKind(trie, false);
        byte[] emptyWire = trie.getProofWire(emptyQuery).orElseThrow();
        int emptyBranches = PoseidonMpfCodec.decode(emptyWire).size();
        var empty = PoseidonMpfBranchWitness.emptyNonInclusion(
                trie.getRootHash(), emptyQuery, emptyWire, emptyBranches);
        assertEquals(emptyBranches, empty.branchCount());
        assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfDifferentLeafWitness.nonInclusion(
                        trie.getRootHash(), emptyQuery, emptyWire, emptyBranches));

        PoseidonMpfTrie one = PoseidonMpfTrie.inMemory();
        one.put(bytes("only-key"), bytes("only-value"));
        byte[] differentQuery = bytes("absent-key");
        byte[] differentWire = one.getProofWire(differentQuery).orElseThrow();
        var different = PoseidonMpfDifferentLeafWitness.nonInclusion(
                one.getRootHash(), differentQuery, differentWire, 2);
        assertEquals(0, different.branches().branchCount());
        assertEquals(64, different.conflictingLeafPath().size());
        assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.emptyNonInclusion(
                        one.getRootHash(), differentQuery, differentWire, 2));
    }

    @Test
    void strictNormalizationRejectsTrailingBytesBeforeCreatingWitness() {
        PoseidonMpfTrie trie = populated();
        byte[] key = bytes("member-1");
        byte[] value = bytes("active");
        byte[] wire = trie.getProofWire(key).orElseThrow();
        byte[] appended = Arrays.copyOf(wire, wire.length + 1);
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfBranchWitness.inclusion(
                trie.getRootHash(), key, value, appended, 8));
    }

    private static PoseidonMpfTrie populated() {
        PoseidonMpfTrie trie = PoseidonMpfTrie.inMemory();
        trie.put(bytes("member-1"), bytes("active"));
        trie.put(bytes("member-2"), bytes("active"));
        trie.put(bytes("member-3"), bytes("suspended"));
        return trie;
    }

    private static byte[] findProofOfKind(PoseidonMpfTrie trie, boolean leaf) {
        for (int index = 0; index < 10_000; index++) {
            byte[] query = bytes("missing-" + index);
            var steps = PoseidonMpfCodec.decode(trie.getProofWire(query).orElseThrow());
            boolean isLeaf = !steps.isEmpty()
                    && steps.getLast().kind() == PoseidonMpfCodec.KIND_LEAF;
            boolean allBranches = steps.stream()
                    .allMatch(step -> step.kind() == PoseidonMpfCodec.KIND_BRANCH);
            if ((leaf && isLeaf) || (!leaf && allBranches)) return query;
        }
        throw new AssertionError("failed to find deterministic proof form");
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
