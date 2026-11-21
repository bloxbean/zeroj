package org.zeroj.merkle.mpf.poseidon.witness;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.UnsignedInteger;
import com.bloxbean.cardano.vds.core.NibblePath;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.annotation.ZkInputMap;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCommitmentScheme;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfHashFunction;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfReference;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import org.zeroj.merkle.mpf.poseidon.circuit.PoseidonMpfCircuitTemplates;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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

    @Test
    void normalizesNonEmptyOddAndEvenForkPrefixesAndNonTerminalLeafStepsToBranchEquivalentWitnesses()
            throws Exception {
        var commitments = new PoseidonMpfCommitmentScheme();
        var hashFn = PoseidonMpfHashFunction.INSTANCE;
        byte[] key = bytes("compact-normalization-key");
        byte[] value = bytes("compact-normalization-value");
        byte[] valueDigest = hashFn.digest(value);
        int[] path = PoseidonMpfHash.digestToNibbles(hashFn.digest(key));

        // 1. ForkStep with non-empty odd (3), even (4), and multi-chunk (35) prefixes.
        byte[] forkSubtreeRoot = hashFn.digest(bytes("fork-subtree-root"));
        int skip = 2;
        int branchPos = skip;
        int meNibble = path[branchPos];
        int otherNibble = (meNibble + 5) & 0x0f;
        byte[] leafCommit = commitments.commitLeaf(
                NibblePath.fromRange(path, branchPos + 1, path.length - branchPos - 1), valueDigest);

        for (int prefixLen : new int[]{3, 4, 35}) {
            byte[] prefix = new byte[prefixLen];
            for (int i = 0; i < prefixLen; i++) {
                prefix[i] = (byte) ((i * 7 + 1) & 0x0f);
            }
            byte[] combined = new byte[prefix.length + forkSubtreeRoot.length];
            System.arraycopy(prefix, 0, combined, 0, prefix.length);
            System.arraycopy(forkSubtreeRoot, 0, combined, prefix.length, forkSubtreeRoot.length);
            byte[] siblingHash = hashFn.digest(combined);

            byte[][] children = new byte[16][];
            children[meNibble] = leafCommit;
            children[otherNibble] = siblingHash;
            byte[] root = commitments.commitBranch(NibblePath.fromRange(path, 0, skip), children, null);

            byte[] forkWire = encodeProof(forkStepCbor(skip, otherNibble, prefix, forkSubtreeRoot));
            byte[] branchWire = encodeProof(branchStepCbor(skip, independentSiblings(children, meNibble)));

            assertTrue(PoseidonMpfReference.including(root, key, value, forkWire),
                    "reference verifier must accept ForkStep with prefixLen=" + prefixLen);
            assertTrue(PoseidonMpfReference.including(root, key, value, branchWire));
            assertArrayEquals(prefix, PoseidonMpfCodec.decode(forkWire).getFirst().forkPrefixBytes());

            PoseidonMpfBranchWitness forkWitness =
                    PoseidonMpfBranchWitness.inclusion(root, key, value, forkWire, 1);
            PoseidonMpfBranchWitness branchWitness =
                    PoseidonMpfBranchWitness.inclusion(root, key, value, branchWire, 1);
            assertEquals(branchWitness.siblings(), forkWitness.siblings(),
                    "ForkStep prefixLen=" + prefixLen + " must normalize identically to BranchStep");
            assertEquals(branchWitness.skip(), forkWitness.skip());

            var circuit = PoseidonMpfCircuitTemplates.inclusion(1);
            var inputs = new ZkInputMap()
                    .put(PoseidonMpfCircuitTemplates.ROOT, PoseidonMpfHash.fieldFromDigestBytes(root))
                    .put(PoseidonMpfCircuitTemplates.VALUE, PoseidonMpfValueCommitment.field(value));
            forkWitness.putInto(inputs);
            assertDoesNotThrow(() -> circuit.calculateWitness(inputs.toWitnessMap(), CurveId.BLS12_381),
                    "ZkMpfInclusion must accept normalized ForkStep prefixLen=" + prefixLen);
        }

        // 2. Non-terminal LeafStep at step 0 followed by a BranchStep at step 1 (both inclusion and empty non-inclusion).
        byte[] siblingLeafKey = bytes("sibling-leaf-key");
        byte[] siblingLeafKeyHash = hashFn.digest(siblingLeafKey);
        int[] siblingLeafPath = PoseidonMpfHash.digestToNibbles(siblingLeafKeyHash);
        // Ensure sibling leaf diverges at nibble 0 (if equal by chance, pick another key).
        for (int attempt = 0; siblingLeafPath[0] == path[0]; attempt++) {
            siblingLeafKey = bytes("sibling-leaf-key-" + attempt);
            siblingLeafKeyHash = hashFn.digest(siblingLeafKey);
            siblingLeafPath = PoseidonMpfHash.digestToNibbles(siblingLeafKeyHash);
        }
        byte[] siblingLeafValueHash = hashFn.digest(bytes("sibling-leaf-value"));
        byte[] siblingLeafCommit = commitments.commitLeaf(
                NibblePath.fromRange(siblingLeafPath, 1, 63), siblingLeafValueHash);

        int childBranchPos = 1;
        int childMe = path[childBranchPos];
        int childOtherA = (childMe + 1) & 0x0f;
        int childOtherB = (childMe + 2) & 0x0f;
        byte[] extraA = hashFn.digest(bytes("child-a"));
        byte[] extraB = hashFn.digest(bytes("child-b"));

        // 2a. Inclusion: step 0 = non-terminal LeafStep, step 1 = BranchStep.
        byte[][] childIncChildren = new byte[16][];
        childIncChildren[childMe] = commitments.commitLeaf(NibblePath.fromRange(path, 2, 62), valueDigest);
        childIncChildren[childOtherA] = extraA;
        childIncChildren[childOtherB] = extraB;
        byte[] childIncRoot = commitments.commitBranch(NibblePath.EMPTY, childIncChildren, null);
        byte[][] topIncChildren = new byte[16][];
        topIncChildren[path[0]] = childIncRoot;
        topIncChildren[siblingLeafPath[0]] = siblingLeafCommit;
        byte[] topIncRoot = commitments.commitBranch(NibblePath.EMPTY, topIncChildren, null);

        byte[] leafStepIncWire = encodeProof(
                leafStepCbor(0, siblingLeafKeyHash, siblingLeafValueHash),
                branchStepCbor(0, independentSiblings(childIncChildren, childMe)));
        byte[] branchOnlyIncWire = encodeProof(
                branchStepCbor(0, independentSiblings(topIncChildren, path[0])),
                branchStepCbor(0, independentSiblings(childIncChildren, childMe)));

        assertTrue(PoseidonMpfReference.including(topIncRoot, key, value, leafStepIncWire));
        assertTrue(PoseidonMpfReference.including(topIncRoot, key, value, branchOnlyIncWire));
        PoseidonMpfBranchWitness leafIncWitness =
                PoseidonMpfBranchWitness.inclusion(topIncRoot, key, value, leafStepIncWire, 2);
        PoseidonMpfBranchWitness branchIncWitness =
                PoseidonMpfBranchWitness.inclusion(topIncRoot, key, value, branchOnlyIncWire, 2);
        assertEquals(branchIncWitness.siblings(), leafIncWitness.siblings());
        var incCircuit2 = PoseidonMpfCircuitTemplates.inclusion(2);
        var incInputs2 = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.ROOT, PoseidonMpfHash.fieldFromDigestBytes(topIncRoot))
                .put(PoseidonMpfCircuitTemplates.VALUE, PoseidonMpfValueCommitment.field(value));
        leafIncWitness.putInto(incInputs2);
        assertDoesNotThrow(() -> incCircuit2.calculateWitness(incInputs2.toWitnessMap(), CurveId.BLS12_381));

        // 2b. Empty non-inclusion: step 0 = non-terminal LeafStep, step 1 = terminal BranchStep with empty slot.
        byte[][] childEmptyChildren = new byte[16][];
        childEmptyChildren[childOtherA] = extraA;
        childEmptyChildren[childOtherB] = extraB;
        byte[] childEmptyRoot = commitments.commitBranch(NibblePath.EMPTY, childEmptyChildren, null);
        byte[][] topEmptyChildren = new byte[16][];
        topEmptyChildren[path[0]] = childEmptyRoot;
        topEmptyChildren[siblingLeafPath[0]] = siblingLeafCommit;
        byte[] topEmptyRoot = commitments.commitBranch(NibblePath.EMPTY, topEmptyChildren, null);

        byte[] leafStepEmptyWire = encodeProof(
                leafStepCbor(0, siblingLeafKeyHash, siblingLeafValueHash),
                branchStepCbor(0, independentSiblings(childEmptyChildren, childMe)));
        byte[] branchOnlyEmptyWire = encodeProof(
                branchStepCbor(0, independentSiblings(topEmptyChildren, path[0])),
                branchStepCbor(0, independentSiblings(childEmptyChildren, childMe)));

        assertTrue(PoseidonMpfReference.excluding(topEmptyRoot, key, leafStepEmptyWire));
        assertTrue(PoseidonMpfReference.excluding(topEmptyRoot, key, branchOnlyEmptyWire));
        PoseidonMpfBranchWitness leafEmptyWitness =
                PoseidonMpfBranchWitness.emptyNonInclusion(topEmptyRoot, key, leafStepEmptyWire, 2);
        PoseidonMpfBranchWitness branchEmptyWitness =
                PoseidonMpfBranchWitness.emptyNonInclusion(topEmptyRoot, key, branchOnlyEmptyWire, 2);
        assertEquals(branchEmptyWitness.siblings(), leafEmptyWitness.siblings());
        var emptyCircuit2 = PoseidonMpfCircuitTemplates.nonInclusionEmpty(2);
        var emptyInputs2 = new ZkInputMap()
                .put(PoseidonMpfCircuitTemplates.ROOT, PoseidonMpfHash.fieldFromDigestBytes(topEmptyRoot));
        leafEmptyWitness.putInto(emptyInputs2);
        assertDoesNotThrow(() -> emptyCircuit2.calculateWitness(emptyInputs2.toWitnessMap(), CurveId.BLS12_381));
    }

    @Test
    void rejectsEveryInvalidForkLeafAndPrefixEncodingPath() {
        byte[] key = bytes("negative-normalization-key");
        int[] path = PoseidonMpfHash.digestToNibbles(PoseidonMpfHashFunction.INSTANCE.digest(key));
        List<BigInteger> pathBig = Arrays.stream(path).mapToObj(BigInteger::valueOf).toList();
        List<BigInteger> zeroNeighbors = List.of(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);

        // ForkStep with neighbor nibble equal to path nibble.
        var collidingFork = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), path[0], 0, List.of(),
                BigInteger.ONE, List.of(), BigInteger.ZERO);
        IllegalArgumentException forkCollision = assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.normalizeBranches(key, List.of(collidingFork), 1, false));
        assertTrue(forkCollision.getMessage().contains("ForkStep neighbor nibble equals path nibble"));

        // LeafStep with neighbor nibble equal to path nibble.
        var collidingLeaf = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_LEAF, 0, List.of(), 0, 0, List.of(),
                BigInteger.ZERO, pathBig, BigInteger.ONE);
        IllegalArgumentException leafCollision = assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.normalizeBranches(key, List.of(collidingLeaf), 1, false));
        assertTrue(leafCollision.getMessage().contains("LeafStep neighbor nibble equals path nibble"));

        // LeafStep with mismatched prefix before branchPos (skip = 2, mismatch at nibble 0).
        var mismatchedLeafPath = new ArrayList<>(pathBig);
        mismatchedLeafPath.set(0, BigInteger.valueOf((path[0] + 1) & 0x0f));
        mismatchedLeafPath.set(2, BigInteger.valueOf((path[2] + 1) & 0x0f));
        var mismatchedLeaf = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_LEAF, 2, List.of(), 0, 0, List.of(),
                BigInteger.ZERO, mismatchedLeafPath, BigInteger.ONE);
        IllegalArgumentException leafPrefixMismatch = assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.normalizeBranches(key, List.of(mismatchedLeaf), 1, false));
        assertTrue(leafPrefixMismatch.getMessage().contains("LeafStep prefix does not match key path"));

        // Step skipping past the end of the 64-nibble path.
        var skipPastEnd = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_BRANCH, 64, zeroNeighbors, 0, 0, List.of(),
                BigInteger.ZERO, List.of(), BigInteger.ZERO);
        IllegalArgumentException skipEx = assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.normalizeBranches(key, List.of(skipPastEnd), 1, false));
        assertTrue(skipEx.getMessage().contains("skips past the end of the path"));

        // emptyNonInclusion (requireFinalBranch = true) rejects terminal ForkStep and terminal LeafStep.
        var validFork = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), (path[0] + 1) & 0x0f, 0, List.of(),
                BigInteger.ONE, List.of(), BigInteger.ZERO);
        IllegalArgumentException termFork = assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.normalizeBranches(key, List.of(validFork), 1, true));
        assertTrue(termFork.getMessage().contains("must terminate in a BranchStep"));

        var validLeafPath = new ArrayList<>(pathBig);
        validLeafPath.set(0, BigInteger.valueOf((path[0] + 1) & 0x0f));
        var validLeaf = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_LEAF, 0, List.of(), 0, 0, List.of(),
                BigInteger.ZERO, validLeafPath, BigInteger.ONE);
        IllegalArgumentException termLeaf = assertThrows(IllegalArgumentException.class, () ->
                PoseidonMpfBranchWitness.normalizeBranches(key, List.of(validLeaf), 1, true));
        assertTrue(termLeaf.getMessage().contains("must terminate in a BranchStep"));

        // Step forkPrefixLength > 64 or < 0.
        assertThrows(IllegalArgumentException.class, () -> new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), 1, 65, List.of(),
                BigInteger.ONE, List.of(), BigInteger.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), 1, -1, List.of(),
                BigInteger.ONE, List.of(), BigInteger.ZERO));

        // forkPrefixBytes: non-empty chunks when length is 0, wrong chunk count, negative chunk, chunk overflow.
        var nonEmptyForZero = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), 1, 0, List.of(BigInteger.ONE),
                BigInteger.ONE, List.of(), BigInteger.ZERO);
        assertThrows(IllegalArgumentException.class, nonEmptyForZero::forkPrefixBytes);

        var wrongChunkCount = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), 1, 35, List.of(BigInteger.ONE),
                BigInteger.ONE, List.of(), BigInteger.ZERO);
        assertThrows(IllegalArgumentException.class, wrongChunkCount::forkPrefixBytes);

        var negativeChunk = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), 1, 2, List.of(BigInteger.ONE.negate()),
                BigInteger.ONE, List.of(), BigInteger.ZERO);
        assertThrows(IllegalArgumentException.class, negativeChunk::forkPrefixBytes);

        var overflowChunk = new PoseidonMpfCodec.Step(
                PoseidonMpfCodec.KIND_FORK, 0, List.of(), 1, 2, List.of(BigInteger.ONE.shiftLeft(16)),
                BigInteger.ONE, List.of(), BigInteger.ZERO);
        assertThrows(IllegalArgumentException.class, overflowChunk::forkPrefixBytes);

        // CBOR wire with fork prefix > 64 bytes rejected at decode.
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(
                encodeProof(forkStepCbor(0, 1, new byte[65], new byte[32]))));

        // CBOR wire with non-nibble fork prefix byte (> 15) or invalid neighborNibble rejected at decode (ADR-0068).
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(
                encodeProof(forkStepCbor(0, 1, new byte[]{0x01, 0x10}, new byte[32]))));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(
                encodeProof(forkStepCbor(0, 1, new byte[]{(byte) 0xFF}, new byte[32]))));
        assertThrows(IllegalArgumentException.class, () -> PoseidonMpfCodec.decode(
                encodeProof(forkStepCbor(0, 16, new byte[]{0x01}, new byte[32]))));
    }

    private static byte[][] independentSiblings(byte[][] children, int meNibble) {
        byte[][] level0 = new byte[16][];
        for (int i = 0; i < 16; i++) {
            level0[i] = children[i] == null ? new byte[32] : children[i].clone();
        }
        byte[][] level1 = new byte[8][];
        for (int i = 0; i < 8; i++) {
            level1[i] = PoseidonMpfHash.digestPair(
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    level0[2 * i], level0[2 * i + 1]);
        }
        byte[][] level2 = new byte[4][];
        for (int i = 0; i < 4; i++) {
            level2[i] = PoseidonMpfHash.digestPair(
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    level1[2 * i], level1[2 * i + 1]);
        }
        byte[][] level3 = new byte[2][];
        for (int i = 0; i < 2; i++) {
            level3[i] = PoseidonMpfHash.digestPair(
                    PoseidonParamsBLS12_381T3.INSTANCE,
                    level2[2 * i], level2[2 * i + 1]);
        }
        return new byte[][]{
                level3[(meNibble >>> 3) ^ 1],
                level2[(meNibble >>> 2) ^ 1],
                level1[(meNibble >>> 1) ^ 1],
                level0[meNibble ^ 1]
        };
    }

    private static Array forkStepCbor(int skip, int neighborNibble, byte[] prefix, byte[] root) {
        Array neighbor = new Array();
        neighbor.setTag(121);
        neighbor.add(new UnsignedInteger(neighborNibble));
        neighbor.add(new ByteString(prefix));
        neighbor.add(new ByteString(root));
        Array step = new Array();
        step.setTag(122);
        step.add(new UnsignedInteger(skip));
        step.add(neighbor);
        return step;
    }

    private static Array leafStepCbor(int skip, byte[] keyHash, byte[] valueHash) {
        Array step = new Array();
        step.setTag(123);
        step.add(new UnsignedInteger(skip));
        step.add(new ByteString(keyHash));
        step.add(new ByteString(valueHash));
        return step;
    }

    private static Array branchStepCbor(int skip, byte[][] siblings) {
        byte[] packed = new byte[4 * 32];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(siblings[i], 0, packed, i * 32, 32);
        }
        Array step = new Array();
        step.setTag(121);
        step.add(new UnsignedInteger(skip));
        step.add(new ByteString(packed));
        return step;
    }

    private static byte[] encodeProof(Array... steps) throws Exception {
        Array proof = new Array();
        for (Array step : steps) proof.add(step);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        new CborEncoder(out).encode(proof);
        return out.toByteArray();
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
