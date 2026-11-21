package org.zeroj.merkle.jmt.poseidon.ccl;

import com.bloxbean.cardano.vds.jmt.JmtEncoding;
import com.bloxbean.cardano.vds.jmt.JmtInternalNode;
import com.bloxbean.cardano.vds.jmt.JmtLeafNode;
import com.bloxbean.cardano.vds.jmt.JmtNode;
import com.bloxbean.cardano.vds.jmt.JmtProof;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import org.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
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
    private static final int MAX_INTERNAL_NODE_ITEMS = 2 + 16; // tag + bitmap + up to 16 child hashes
    private static final int MAX_NODE_BYTES = 1024;            // v1 internal node with 16 x 32B hashes is ~550B

    /**
     * Independent wire-proof verification for the Poseidon JMT v1 statement.
     *
     * <p>Parses the CBOR classic JMT proof array iteratively with strict depth,
     * count, and remaining-length bounds (RFC 8949 §10) before calling the CCL
     * node decoder, enforces v1 non-compressed step-by-step path traversal
     * without skipped levels, validates canonical Poseidon field digests, and
     * recomputes the root via {@link PoseidonJmtCommitments}.</p>
     */
    public static boolean verifyWire(
            byte[] expectedRoot,
            byte[] key,
            byte[] expectedValue,
            boolean including,
            byte[] proofWire) {
        if (expectedRoot == null || key == null || proofWire == null
                || proofWire.length == 0
                || proofWire.length > MAX_WIRE_BYTES
                || including != (expectedValue != null)) {
            return false;
        }
        try {
            PoseidonJmtHash.decode(expectedRoot);
            byte[] queryKeyHash = PoseidonJmtHash.digest(key);
            int[] queryPath = PoseidonJmtHash.nibbles(queryKeyHash);

            List<JmtNode> nodes = decodeBoundedWireNodes(proofWire, queryPath.length + 1);
            if (nodes == null) {
                return false;
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

    /**
     * Iterative, zero-recursion bounded CBOR parser for the v1 Classic JMT proof wire schema:
     * a single definite-length CBOR array of at most {@code maxNodes} definite-length byte strings,
     * each containing a flat v1 node array validated before calling {@link JmtEncoding#decode}.
     */
    private static List<JmtNode> decodeBoundedWireNodes(byte[] wire, int maxNodes) {
        int[] cursor = {0};
        long countLong = readDefiniteHeader(wire, cursor, 4); // major 4 = array
        if (countLong < 0 || countLong > maxNodes) {
            return null;
        }
        int count = (int) countLong;
        List<JmtNode> nodes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            long lenLong = readDefiniteHeader(wire, cursor, 2); // major 2 = byte string
            if (lenLong <= 0 || lenLong > MAX_NODE_BYTES || lenLong > wire.length - cursor[0]) {
                return null;
            }
            int len = (int) lenLong;
            int start = cursor[0];
            cursor[0] = start + len;
            if (!isValidFlatV1NodeCbor(wire, start, len)) {
                return null;
            }
            byte[] nodeBytes = Arrays.copyOfRange(wire, start, start + len);
            nodes.add(JmtEncoding.decode(nodeBytes));
        }
        if (cursor[0] != wire.length) {
            return null;
        }
        return nodes;
    }

    /**
     * Validates that {@code wire[offset..offset+length)} is a single flat definite-length CBOR
     * array matching either a v1 JMT internal node (tag + bitmap + popcount(bitmap) 32-byte
     * child hashes, no compressed path) or a v1 JMT leaf node (tag + 32-byte keyHash + 32-byte
     * valueHash), with zero nested containers and zero trailing bytes.
     */
    private static boolean isValidFlatV1NodeCbor(byte[] wire, int offset, int length) {
        int end = offset + length;
        int[] cursor = {offset};
        long itemCountLong = readDefiniteHeader(wire, cursor, end, 4); // major 4 = array
        if (itemCountLong < 2 || itemCountLong > MAX_INTERNAL_NODE_ITEMS) {
            return false;
        }
        int itemCount = (int) itemCountLong;
        // Item 0: 1-byte node tag ByteString
        long tagLen = readDefiniteHeader(wire, cursor, end, 2);
        if (tagLen != 1 || cursor[0] >= end) {
            return false;
        }
        int tag = wire[cursor[0]++] & 0xFF;
        if (tag == 0) {
            // Internal node (v1 non-compressed): [tag(1B), bitmap(uint 0..65535), childHash_0..k(32B each)]
            long bitmap = readDefiniteHeader(wire, cursor, end, 0); // major 0 = unsigned int
            if (bitmap < 0 || bitmap > 0xFFFFL) {
                return false;
            }
            int expectedHashes = Integer.bitCount((int) bitmap);
            if (itemCount != 2 + expectedHashes) {
                return false;
            }
            for (int i = 0; i < expectedHashes; i++) {
                long hashLen = readDefiniteHeader(wire, cursor, end, 2);
                if (hashLen != PoseidonJmtProfile.DIGEST_BYTES || hashLen > end - cursor[0]) {
                    return false;
                }
                cursor[0] += (int) hashLen;
            }
            return cursor[0] == end;
        } else if (tag == 1) {
            // Leaf node: [tag(1B), keyHash(32B), valueHash(32B)]
            if (itemCount != 3) {
                return false;
            }
            for (int i = 0; i < 2; i++) {
                long hashLen = readDefiniteHeader(wire, cursor, end, 2);
                if (hashLen != PoseidonJmtProfile.DIGEST_BYTES || hashLen > end - cursor[0]) {
                    return false;
                }
                cursor[0] += (int) hashLen;
            }
            return cursor[0] == end;
        }
        return false;
    }

    private static long readDefiniteHeader(byte[] data, int[] cursor, int expectedMajor) {
        return readDefiniteHeader(data, cursor, data.length, expectedMajor);
    }

    private static long readDefiniteHeader(byte[] data, int[] cursor, int end, int expectedMajor) {
        int pos = cursor[0];
        if (pos >= end) {
            return -1;
        }
        int initial = data[pos++] & 0xFF;
        int major = initial >>> 5;
        int ai = initial & 0x1F;
        if (major != expectedMajor) {
            return -1;
        }
        long value;
        if (ai < 24) {
            value = ai;
        } else if (ai == 24) {
            if (pos + 1 > end) return -1;
            value = data[pos++] & 0xFFL;
        } else if (ai == 25) {
            if (pos + 2 > end) return -1;
            value = ((data[pos] & 0xFFL) << 8) | (data[pos + 1] & 0xFFL);
            pos += 2;
        } else if (ai == 26) {
            if (pos + 4 > end) return -1;
            value = ((data[pos] & 0xFFL) << 24)
                    | ((data[pos + 1] & 0xFFL) << 16)
                    | ((data[pos + 2] & 0xFFL) << 8)
                    | (data[pos + 3] & 0xFFL);
            pos += 4;
        } else if (ai == 27) {
            if (pos + 8 > end) return -1;
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (data[pos++] & 0xFFL);
            }
            if (v < 0) return -1; // reject > Long.MAX_VALUE
            value = v;
        } else {
            // Reject reserved additional info (28..30) and indefinite-length (31)
            return -1;
        }
        cursor[0] = pos;
        return value;
    }

    private static boolean equal(byte[] left, byte[] right) {
        return left != null && right != null && MessageDigest.isEqual(left, right);
    }
}
