package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtCommitments;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/** Canonical fixed-bound JMT authentication path shared by operation-specific witnesses. */
public final class PoseidonJmtPathWitness {
    public static final Names DEFAULT_NAMES =
            new Names("jmt_key_nibble", "jmt_sibling", "jmt_valid");

    private final List<BigInteger> keyNibbles;
    private final List<List<BigInteger>> siblings;
    private final List<BigInteger> valid;
    private final int depth;

    private PoseidonJmtPathWitness(
            List<BigInteger> keyNibbles,
            List<List<BigInteger>> siblings,
            List<BigInteger> valid,
            int depth) {
        this.keyNibbles = immutableFlat(keyNibbles, "keyNibbles");
        this.siblings = siblings.stream()
                .map(row -> immutableFlat(row, "siblings row"))
                .toList();
        this.valid = immutableFlat(valid, "valid");
        this.depth = depth;
    }

    static PoseidonJmtPathWitness normalize(byte[] key, JmtProof proof, int maxLevels) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(proof, "proof");
        requireBound(maxLevels);
        if (proof.steps().size() > maxLevels) {
            throw new IllegalArgumentException("JMT proof depth " + proof.steps().size()
                    + " exceeds bound " + maxLevels);
        }

        int[] queryPath = PoseidonJmtHash.nibbles(PoseidonJmtHash.digest(key));
        List<BigInteger> query = new ArrayList<>(queryPath.length);
        for (int nibble : queryPath) query.add(BigInteger.valueOf(nibble));
        List<List<BigInteger>> normalized = new ArrayList<>(maxLevels);
        List<BigInteger> valid = new ArrayList<>(maxLevels);

        for (int depth = 0; depth < proof.steps().size(); depth++) {
            JmtProof.BranchStep step = proof.steps().get(depth);
            if (step.prefix() == null || step.prefix().length() != depth) {
                throw new IllegalArgumentException("JMT proof contains a depth gap at step " + depth);
            }
            int[] prefix = step.prefix().getNibbles();
            for (int index = 0; index < prefix.length; index++) {
                if (prefix[index] != queryPath[index]) {
                    throw new IllegalArgumentException("JMT proof prefix does not bind the query key");
                }
            }
            if (step.childIndex() != queryPath[depth]) {
                throw new IllegalArgumentException("JMT proof child index does not bind the query key");
            }
            byte[][] children = step.childHashes();
            if (children == null || children.length != PoseidonJmtProfile.RADIX) {
                throw new IllegalArgumentException("JMT BranchStep must expose sixteen child slots");
            }
            for (int child = 0; child < children.length; child++) {
                if (children[child] != null) PoseidonJmtHash.decode(children[child]);
            }
            List<BigInteger> row = new ArrayList<>(PoseidonJmtProfile.BRANCH_LEVELS);
            for (int level = 0; level < PoseidonJmtProfile.BRANCH_LEVELS; level++) {
                row.add(PoseidonJmtHash.decode(siblingSubtree(children, step.childIndex(), level)));
            }
            normalized.add(List.copyOf(row));
            valid.add(BigInteger.ONE);
        }
        while (normalized.size() < maxLevels) {
            normalized.add(Collections.nCopies(PoseidonJmtProfile.BRANCH_LEVELS, BigInteger.ZERO));
            valid.add(BigInteger.ZERO);
        }
        return new PoseidonJmtPathWitness(query, normalized, valid, proof.steps().size());
    }

    private static byte[] siblingSubtree(byte[][] children, int childIndex, int level) {
        int width = 1 << level;
        int start = (((childIndex >>> level) ^ 1) << level);
        byte[][] current = new byte[width][];
        for (int offset = 0; offset < width; offset++) {
            byte[] child = children[start + offset];
            current[offset] = child == null ? PoseidonJmtCommitments.empty() : child.clone();
        }
        for (int binaryLevel = 0; binaryLevel < level; binaryLevel++) {
            byte[][] next = new byte[current.length / 2][];
            for (int index = 0; index < current.length; index += 2) {
                next[index / 2] = PoseidonJmtCommitments.binaryPair(
                        binaryLevel, current[index], current[index + 1]);
            }
            current = next;
        }
        return current[0];
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        return putInto(inputs, DEFAULT_NAMES);
    }

    public ZkInputMap putInto(ZkInputMap inputs, Names names) {
        Objects.requireNonNull(inputs, "inputs");
        Objects.requireNonNull(names, "names");
        return inputs.putArray(names.keyNibbles(), keyNibbles)
                .putNestedArray(names.siblings(), siblings)
                .putArray(names.valid(), valid);
    }

    public List<BigInteger> keyNibbles() { return keyNibbles; }
    public List<List<BigInteger>> siblings() { return siblings; }
    public List<BigInteger> valid() { return valid; }
    public int depth() { return depth; }
    public int maxLevels() { return valid.size(); }

    public record Names(String keyNibbles, String siblings, String valid) {
        public Names {
            requireName(keyNibbles, "keyNibbles");
            requireName(siblings, "siblings");
            requireName(valid, "valid");
        }

        private static void requireName(String value, String label) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(label + " signal name must not be blank");
            }
        }
    }

    static void requireBound(int maxLevels) {
        if (maxLevels < 0 || maxLevels > PoseidonJmtProfile.KEY_NIBBLES) {
            throw new IllegalArgumentException("maxLevels must be in [0, 64]");
        }
    }

    private static List<BigInteger> immutableFlat(List<BigInteger> values, String name) {
        Objects.requireNonNull(values, name);
        for (int index = 0; index < values.size(); index++) {
            Objects.requireNonNull(values.get(index), name + "[" + index + "]");
        }
        return List.copyOf(values);
    }
}
