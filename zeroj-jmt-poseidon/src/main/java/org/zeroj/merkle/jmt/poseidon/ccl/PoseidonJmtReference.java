package org.zeroj.merkle.jmt.poseidon.ccl;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.Array;
import co.nstant.in.cbor.model.ByteString;
import co.nstant.in.cbor.model.DataItem;
import com.bloxbean.cardano.vds.jmt.JmtEncoding;
import com.bloxbean.cardano.vds.jmt.JmtInternalNode;
import com.bloxbean.cardano.vds.jmt.JmtLeafNode;
import com.bloxbean.cardano.vds.jmt.JmtNode;
import com.bloxbean.cardano.vds.jmt.JmtProof;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

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

    private static final int MAX_WIRE_BYTES = 1_048_576;

    /**
     * Independent wire-proof verification for the Poseidon JMT v1 statement.
     *
     * <p>Decodes the CBOR classic JMT proof array, enforces v1 non-compressed
     * step-by-step path traversal without skipped levels, validates canonical
     * Poseidon field digests, and recomputes the root via
     * {@link PoseidonJmtCommitments}.</p>
     */
    public static boolean verifyWire(
            byte[] expectedRoot,
            byte[] key,
            byte[] expectedValue,
            boolean including,
            byte[] proofWire) {
        if (expectedRoot == null || key == null || proofWire == null
                || proofWire.length > MAX_WIRE_BYTES
                || including != (expectedValue != null)) {
            return false;
        }
        try {
            PoseidonJmtHash.decode(expectedRoot);
            byte[] queryKeyHash = PoseidonJmtHash.digest(key);
            int[] queryPath = PoseidonJmtHash.nibbles(queryKeyHash);

            List<DataItem> top = new CborDecoder(new ByteArrayInputStream(proofWire)).decode();
            if (top.size() != 1 || !(top.get(0) instanceof Array array)) {
                return false;
            }
            List<DataItem> items = array.getDataItems();
            if (items.size() > queryPath.length + 1) {
                return false;
            }

            List<JmtNode> nodes = new ArrayList<>(items.size());
            for (DataItem item : items) {
                if (!(item instanceof ByteString bs)) {
                    return false;
                }
                nodes.add(JmtEncoding.decode(bs.getBytes()));
            }

            if (nodes.isEmpty()) {
                return !including && equal(expectedRoot, PoseidonJmtCommitments.empty());
            }

            List<JmtInternalNode> branches = new ArrayList<>(nodes.size());
            JmtLeafNode terminalLeaf = null;
            boolean missingBranchTerminal = false;
            for (int depth = 0; depth < nodes.size(); depth++) {
                JmtNode node = nodes.get(depth);
                boolean isLast = depth == nodes.size() - 1;
                if (node instanceof JmtInternalNode internal) {
                    if (internal.compressedPath() != null || depth >= queryPath.length) {
                        return false;
                    }
                    int bit = (internal.bitmap() >>> queryPath[depth]) & 1;
                    branches.add(internal);
                    if (bit == 0) {
                        if (!isLast) {
                            return false;
                        }
                        missingBranchTerminal = true;
                    }
                } else if (node instanceof JmtLeafNode leaf) {
                    if (!isLast) {
                        return false;
                    }
                    terminalLeaf = leaf;
                } else {
                    return false;
                }
            }

            byte[] current;
            if (terminalLeaf != null) {
                byte[] leafKey = terminalLeaf.keyHash();
                byte[] leafValue = terminalLeaf.valueHash();
                PoseidonJmtHash.decode(leafKey);
                PoseidonJmtHash.decode(leafValue);
                if (including) {
                    if (!equal(queryKeyHash, leafKey)) return false;
                    byte[] expectedValueHash = PoseidonJmtHash.digest(expectedValue);
                    if (!equal(expectedValueHash, leafValue)) return false;
                } else {
                    if (equal(queryKeyHash, leafKey)) return false;
                    int[] conflictingPath = PoseidonJmtHash.nibbles(leafKey);
                    for (int i = 0; i < branches.size(); i++) {
                        if (conflictingPath[i] != queryPath[i]) return false;
                    }
                }
                current = PoseidonJmtCommitments.leaf(leafKey, leafValue);
            } else if (missingBranchTerminal) {
                if (including) {
                    return false;
                }
                current = null;
            } else {
                return false;
            }

            for (int depth = branches.size() - 1; depth >= 0; depth--) {
                JmtInternalNode internal = branches.get(depth);
                byte[][] children = unpackChildren(internal);
                if (children == null) {
                    return false;
                }
                int slot = queryPath[depth];
                if (missingBranchTerminal && depth == branches.size() - 1) {
                    if (children[slot] != null) {
                        return false;
                    }
                } else {
                    if (children[slot] == null || !equal(children[slot], current)) {
                        return false;
                    }
                }
                current = PoseidonJmtCommitments.branch(children);
            }
            return equal(expectedRoot, current);
        } catch (Exception malformed) {
            return false;
        }
    }

    private static byte[][] unpackChildren(JmtInternalNode internal) {
        int bitmap = internal.bitmap();
        byte[][] packed = internal.childHashes();
        if (packed == null || packed.length != Integer.bitCount(bitmap & 0xFFFF)) {
            return null;
        }
        byte[][] children = new byte[16][];
        int cursor = 0;
        for (int i = 0; i < 16; i++) {
            if (((bitmap >>> i) & 1) != 0) {
                byte[] hash = packed[cursor++];
                if (hash == null) {
                    return null;
                }
                PoseidonJmtHash.decode(hash);
                children[i] = hash.clone();
            }
        }
        return children;
    }

    private static boolean equal(byte[] left, byte[] right) {
        return left != null && right != null && MessageDigest.isEqual(left, right);
    }
}
