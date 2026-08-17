package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Host-side definition of the Poseidon JMT v1 leaf and radix-16 branch commitments. */
public final class PoseidonJmtCommitments {
    private static final byte[] EMPTY = PoseidonJmtHash.encode(PoseidonJmtHash.compress(
            PoseidonJmtProfile.PARAMS, PoseidonJmtProfile.DOMAIN_EMPTY,
            BigInteger.ZERO, BigInteger.ZERO));
    private static final byte[][] EMPTY_SUBTREES = emptySubtrees();

    private PoseidonJmtCommitments() {}

    public static byte[] empty() {
        return EMPTY.clone();
    }

    /** Empty sibling commitment at the requested bottom-up binary branch level. */
    public static byte[] emptySubtree(int level) {
        if (level < 0 || level >= PoseidonJmtProfile.BRANCH_LEVELS) {
            throw new IllegalArgumentException("empty subtree level must be in [0, 3]");
        }
        return EMPTY_SUBTREES[level].clone();
    }

    /** One domain-separated binary node used inside the fixed radix-16 branch tree. */
    public static byte[] binaryPair(int level, byte[] left, byte[] right) {
        if (level < 0 || level >= PoseidonJmtProfile.BRANCH_LEVELS) {
            throw new IllegalArgumentException("binary branch level must be in [0, 3]");
        }
        return pair(level, requireDigest(left, "left"), requireDigest(right, "right"));
    }

    public static byte[] leaf(byte[] keyHash, byte[] valueHash) {
        BigInteger key = PoseidonJmtHash.decode(keyHash);
        BigInteger value = PoseidonJmtHash.decode(valueHash);
        return PoseidonJmtHash.encode(PoseidonJmtHash.compress(
                PoseidonJmtProfile.PARAMS,
                PoseidonJmtProfile.DOMAIN_LEAF,
                key,
                value));
    }

    /**
     * Commits sixteen logical child slots. CCL's dev1 tree and wire verifier
     * deliberately commit the child vector independently of compressed store
     * prefixes; full-key binding is provided by {@link #leaf(byte[], byte[])}.
     */
    public static byte[] branch(byte[][] children) {
        Objects.requireNonNull(children, "children");
        if (children.length != PoseidonJmtProfile.RADIX) {
            throw new IllegalArgumentException("JMT branch must have exactly 16 child slots");
        }
        byte[][] level = new byte[children.length][];
        for (int i = 0; i < children.length; i++) level[i] = childOrEmpty(children[i]);
        for (int depth = 0; depth < PoseidonJmtProfile.BRANCH_LEVELS; depth++) {
            byte[][] next = new byte[level.length / 2][];
            for (int i = 0; i < level.length; i += 2) {
                next[i / 2] = pair(depth, level[i], level[i + 1]);
            }
            level = next;
        }
        return level[0];
    }

    /** Reconstructs one branch from four bottom-up binary siblings. */
    public static byte[] branchPath(int childIndex, byte[] child, List<byte[]> siblings) {
        if (childIndex < 0 || childIndex >= PoseidonJmtProfile.RADIX) {
            throw new IllegalArgumentException("childIndex must be in [0, 15]");
        }
        Objects.requireNonNull(siblings, "siblings");
        if (siblings.size() != PoseidonJmtProfile.BRANCH_LEVELS) {
            throw new IllegalArgumentException("a JMT branch path requires exactly four siblings");
        }
        byte[] current = childOrEmpty(child);
        for (int level = 0; level < siblings.size(); level++) {
            byte[] sibling = requireDigest(siblings.get(level), "siblings[" + level + "]");
            current = ((childIndex >>> level) & 1) == 0
                    ? pair(level, current, sibling)
                    : pair(level, sibling, current);
        }
        return current;
    }

    private static byte[] pair(int level, byte[] left, byte[] right) {
        return PoseidonJmtHash.encode(PoseidonJmtHash.compress(
                PoseidonJmtProfile.PARAMS,
                PoseidonJmtProfile.branchDomain(level),
                PoseidonJmtHash.decode(left),
                PoseidonJmtHash.decode(right)));
    }

    private static byte[] childOrEmpty(byte[] child) {
        if (child == null) return empty();
        return requireDigest(child, "child");
    }

    private static byte[] requireDigest(byte[] digest, String name) {
        Objects.requireNonNull(digest, name);
        PoseidonJmtHash.decode(digest);
        return Arrays.copyOf(digest, digest.length);
    }

    private static byte[][] emptySubtrees() {
        byte[][] output = new byte[PoseidonJmtProfile.BRANCH_LEVELS][];
        output[0] = EMPTY.clone();
        for (int level = 1; level < output.length; level++) {
            output[level] = pair(level - 1, output[level - 1], output[level - 1]);
        }
        return output;
    }
}
