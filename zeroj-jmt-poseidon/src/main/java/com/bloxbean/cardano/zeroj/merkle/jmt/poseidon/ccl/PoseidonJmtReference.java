package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;

import java.security.MessageDigest;

/** Independent object-proof traversal for the Poseidon JMT v1 statement. */
public final class PoseidonJmtReference {
    private PoseidonJmtReference() {}

    public static boolean including(
            byte[] expectedRoot, byte[] key, byte[] expectedValue, JmtProof proof) {
        return verify(expectedRoot, key, expectedValue, true, proof);
    }

    public static boolean excluding(byte[] expectedRoot, byte[] key, JmtProof proof) {
        return verify(expectedRoot, key, null, false, proof);
    }

    public static boolean verify(
            byte[] expectedRoot,
            byte[] key,
            byte[] expectedValue,
            boolean including,
            JmtProof proof) {
        if (expectedRoot == null || key == null || proof == null
                || including != (expectedValue != null)) {
            return false;
        }
        try {
            PoseidonJmtHash.decode(expectedRoot);
            byte[] queryKeyHash = PoseidonJmtHash.digest(key);
            int[] queryPath = PoseidonJmtHash.nibbles(queryKeyHash);
            byte[] current;
            if (including) {
                if (proof.type() != JmtProof.ProofType.INCLUSION
                        || !equal(queryKeyHash, proof.leafKeyHash())) return false;
                byte[] expectedValueHash = PoseidonJmtHash.digest(expectedValue);
                if (!equal(expectedValueHash, proof.valueHash())) return false;
                current = PoseidonJmtCommitments.leaf(queryKeyHash, expectedValueHash);
            } else if (proof.type() == JmtProof.ProofType.NON_INCLUSION_EMPTY) {
                current = PoseidonJmtCommitments.empty();
            } else if (proof.type() == JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF) {
                byte[] conflictingKey = proof.conflictingKeyHash();
                byte[] conflictingValue = proof.conflictingValueHash();
                PoseidonJmtHash.decode(conflictingKey);
                PoseidonJmtHash.decode(conflictingValue);
                if (equal(queryKeyHash, conflictingKey)) return false;
                current = PoseidonJmtCommitments.leaf(conflictingKey, conflictingValue);
            } else {
                return false;
            }

            for (int stepIndex = 0; stepIndex < proof.steps().size(); stepIndex++) {
                var step = proof.steps().get(stepIndex);
                int prefixLength = step.prefix().length();
                // CCL pre5 JMT proofs have one branch per key nibble and do not
                // support compressed/skipped levels. This equality is a
                // soundness rule because v1 branch commitments deliberately
                // do not bind the object-only prefix metadata.
                if (prefixLength != stepIndex || stepIndex >= queryPath.length) return false;
                int[] prefix = step.prefix().getNibbles();
                for (int i = 0; i < prefix.length; i++) {
                    if (prefix[i] != queryPath[i]) return false;
                }
                if (step.childIndex() != queryPath[stepIndex]) return false;
            }
            if (proof.type() == JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF) {
                int[] conflictingPath = PoseidonJmtHash.nibbles(proof.conflictingKeyHash());
                // A root that is itself a leaf has no branch steps. Full-key
                // inequality above is sufficient for that valid CCL form.
                for (int i = 0; i < proof.steps().size(); i++) {
                    if (conflictingPath[i] != queryPath[i]) return false;
                }
            }

            for (int index = proof.steps().size() - 1; index >= 0; index--) {
                var step = proof.steps().get(index);
                byte[][] supplied = step.childHashes();
                if (supplied == null || supplied.length != 16) return false;
                byte[][] children = new byte[16][];
                for (int child = 0; child < children.length; child++) {
                    children[child] = supplied[child] == null ? null : supplied[child].clone();
                }
                children[step.childIndex()] = current;
                current = PoseidonJmtCommitments.branch(children);
            }
            return equal(expectedRoot, current);
        } catch (RuntimeException malformed) {
            return false;
        }
    }

    private static boolean equal(byte[] left, byte[] right) {
        return left != null && right != null && MessageDigest.isEqual(left, right);
    }
}
