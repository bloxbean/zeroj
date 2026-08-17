package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.core.NibblePath;
import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProofVerifier;
import com.bloxbean.cardano.vds.jmt.store.InMemoryJmtStore;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
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
