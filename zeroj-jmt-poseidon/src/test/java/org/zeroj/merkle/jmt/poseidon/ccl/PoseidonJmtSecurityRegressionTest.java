package org.zeroj.merkle.jmt.poseidon.ccl;

import co.nstant.in.cbor.CborEncoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.vds.jmt.JmtInternalNode;
import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProofVerifier;
import com.bloxbean.cardano.vds.jmt.store.InMemoryJmtStore;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonJmtSecurityRegressionTest {

    @Test
    void putTakesOwnershipOfCallerArraysAndMapContents() {
        var tree = new PoseidonJmtTree(new InMemoryJmtStore());
        byte[] key = bytes("owned-key");
        byte[] value = bytes("owned-value");
        byte[] committedKey = key.clone();
        byte[] committedValue = value.clone();
        var updates = new LinkedHashMap<byte[], byte[]>();
        updates.put(key, value);

        tree.put(1, updates);
        key[0] ^= 0x7f;
        value[0] ^= 0x7f;
        updates.clear();

        assertArrayEquals(committedValue, tree.get(committedKey, 1).orElseThrow());
        assertTrue(tree.get(key, 1).isEmpty());
    }

    @Test
    void acceptsHonestZeroStepDifferentLeafButRejectsStatementTypeConfusion() {
        var tree = new PoseidonJmtTree(new InMemoryJmtStore());
        var entries = new LinkedHashMap<byte[], byte[]>();
        entries.put(bytes("only-key"), bytes("only-value"));
        var commit = tree.put(1, entries);

        byte[] missing = bytes("missing-key");
        JmtProof proof = tree.getProof(missing, 1).orElseThrow();
        byte[] wire = tree.getProofWire(missing, 1).orElseThrow();
        assertEquals(JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF, proof.type());
        assertTrue(proof.steps().isEmpty(), "a root leaf has no branch steps");
        assertTrue(PoseidonJmtReference.excluding(commit.rootHash(), missing, proof));
        assertTrue(tree.verifyNonInclusionProof(commit.rootHash(), missing, proof));
        assertTrue(tree.verifyProofWire(commit.rootHash(), missing, null, false, wire));

        byte[] invented = bytes("invented-value");
        assertFalse(tree.verifyProof(commit.rootHash(), missing, invented, proof));
        assertFalse(tree.verifyInclusionProof(commit.rootHash(), missing, invented, proof));
        assertFalse(tree.verifyProofWire(commit.rootHash(), missing, invented, false, wire));
        assertFalse(PoseidonJmtReference.verify(
                commit.rootHash(), missing, invented, false, proof));
    }

    @Test
    void rejectsGapRelabelingThatCouldForgeAbsenceForPresentKey() throws Exception {
        byte[] key = bytes("present-key");
        byte[] value = bytes("present-value");
        int[] path = PoseidonJmtHash.nibbles(PoseidonJmtHash.digest(key));
        for (int suffix = 0; path[0] == path[1]; suffix++) {
            key = bytes("present-key-" + suffix);
            path = PoseidonJmtHash.nibbles(PoseidonJmtHash.digest(key));
        }

        byte[][] children = new byte[16][];
        byte[] keyHash = PoseidonJmtHash.digest(key);
        children[path[0]] = PoseidonJmtCommitments.leaf(
                keyHash, PoseidonJmtHash.digest(value));
        byte[] root = PoseidonJmtCommitments.branch(children);

        // This claims a depth-one branch even though it authenticates the root
        // branch. Since branch commitments are prefix-independent, the old
        // merely-increasing check reconstructed root while selecting an empty
        // slot at path[1] and falsely proved this present key absent.
        var forgedStep = new JmtProof.BranchStep(
                NibblePath.of(path[0]), cloneChildren(children), path[1],
                false, 0, NibblePath.EMPTY, null, null, null);
        JmtProof forged = nonInclusionEmpty(List.of(forgedStep));

        assertFalse(PoseidonJmtReference.excluding(root, key, forged));
        assertFalse(JmtProofVerifier.verify(
                root, key, null, forged,
                new PoseidonJmtHashFunction(), new PoseidonJmtCommitmentScheme()));
        assertFalse(new PoseidonJmtTree(new InMemoryJmtStore())
                .verifyNonInclusionProof(root, key, forged));

        // Wire-level equivalent: compressedPath on an internal node attempting to skip depth 0.
        int bitmap = 1 << path[0];
        var compressedInternal = JmtInternalNode.of(
                bitmap, new byte[][]{children[path[0]]}, new byte[]{(byte) path[0]});
        Array wireArr = new Array();
        wireArr.add(new ByteString(compressedInternal.encode()));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new CborEncoder(baos).encode(wireArr);
        byte[] forgedWire = baos.toByteArray();

        assertFalse(PoseidonJmtReference.verifyWire(root, key, null, false, forgedWire));
        assertFalse(new PoseidonJmtTree(new InMemoryJmtStore())
                .verifyProofWire(root, key, null, false, forgedWire));
    }

    @Test
    void wireProofRejectsDeepCborNestingOverCountAndNestedNodeCbor() throws Exception {
        var tree = new PoseidonJmtTree(new InMemoryJmtStore());
        var entries = new LinkedHashMap<byte[], byte[]>();
        entries.put(bytes("k1"), bytes("v1"));
        entries.put(bytes("k2"), bytes("v2"));
        var commit = tree.put(1, entries);

        // Positive controls: honest inclusion and non-inclusion wire proofs verify cleanly.
        byte[] inclusionWire = tree.getProofWire(bytes("k1"), 1).orElseThrow();
        byte[] nonInclusionWire = tree.getProofWire(bytes("missing"), 1).orElseThrow();
        assertTrue(tree.verifyProofWire(commit.rootHash(), bytes("k1"), bytes("v1"), true, inclusionWire));
        assertTrue(tree.verifyProofWire(commit.rootHash(), bytes("missing"), null, false, nonInclusionWire));

        // 1. Deeply nested top-level CBOR (300 KB of 1-element array headers 0x81) must return
        //    false without StackOverflowError.
        byte[] deepTopLevel = new byte[300_000];
        Arrays.fill(deepTopLevel, (byte) 0x81);
        assertFalse(PoseidonJmtReference.verifyWire(commit.rootHash(), bytes("k1"), bytes("v1"), true, deepTopLevel));
        assertFalse(tree.verifyProofWire(commit.rootHash(), bytes("k1"), bytes("v1"), true, deepTopLevel));

        // 2. Top-level array exceeding max 65 node entries must return false.
        Array overCount = new Array();
        for (int i = 0; i < 66; i++) {
            overCount.add(new ByteString(new byte[4]));
        }
        ByteArrayOutputStream overBaos = new ByteArrayOutputStream();
        new CborEncoder(overBaos).encode(overCount);
        assertFalse(PoseidonJmtReference.verifyWire(
                commit.rootHash(), bytes("k1"), bytes("v1"), true, overBaos.toByteArray()));

        // 3. Nested CBOR inside a node byte string must be rejected before JmtEncoding.decode.
        byte[] deepNode = new byte[10_000];
        Arrays.fill(deepNode, (byte) 0x81);
        Array embeddedDeep = new Array();
        embeddedDeep.add(new ByteString(deepNode));
        ByteArrayOutputStream embeddedBaos = new ByteArrayOutputStream();
        new CborEncoder(embeddedBaos).encode(embeddedDeep);
        assertFalse(PoseidonJmtReference.verifyWire(
                commit.rootHash(), bytes("k1"), bytes("v1"), true, embeddedBaos.toByteArray()));

        // 4. Trailing bytes after a valid wire proof must return false.
        byte[] trailing = Arrays.copyOf(inclusionWire, inclusionWire.length + 1);
        assertFalse(PoseidonJmtReference.verifyWire(commit.rootHash(), bytes("k1"), bytes("v1"), true, trailing));
    }

    private static JmtProof nonInclusionEmpty(List<JmtProof.BranchStep> steps) throws Exception {
        Method factory = JmtProof.class.getDeclaredMethod("nonInclusionEmpty", List.class);
        factory.setAccessible(true);
        return (JmtProof) factory.invoke(null, steps);
    }

    private static byte[][] cloneChildren(byte[][] children) {
        byte[][] copy = new byte[children.length][];
        for (int index = 0; index < children.length; index++) {
            copy[index] = children[index] == null ? null : children[index].clone();
        }
        return copy;
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
