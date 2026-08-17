package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfHashFunction;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfReference;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Canonical fixed-bound witness for an MPF path made only of CCL BranchSteps.
 * Proof-form selection happens in the factory method, before circuit input is
 * created; it is never represented by a witness flag.
 */
public final class PoseidonMpfBranchWitness {
    public static final Names DEFAULT_NAMES =
            new Names("key_path", "mpf_branch_skip", "mpf_branch_sibling", "mpf_branch_valid");

    private final List<BigInteger> keyPath;
    private final List<BigInteger> skip;
    private final List<List<BigInteger>> siblings;
    private final List<BigInteger> valid;
    private final int branchCount;

    private PoseidonMpfBranchWitness(
            List<BigInteger> keyPath,
            List<BigInteger> skip,
            List<List<BigInteger>> siblings,
            List<BigInteger> valid,
            int branchCount) {
        this.keyPath = copyFlat(keyPath, "keyPath");
        this.skip = copyFlat(skip, "skip");
        this.siblings = siblings.stream().map(row -> copyFlat(row, "siblings row")).toList();
        this.valid = copyFlat(valid, "valid");
        this.branchCount = branchCount;
    }

    /** Strictly verifies and normalizes an inclusion proof containing only branches. */
    public static PoseidonMpfBranchWitness inclusion(
            byte[] root, byte[] key, byte[] value, byte[] proofWire, int maxBranches) {
        if (!PoseidonMpfReference.including(root, key, value, proofWire)) {
            throw new IllegalArgumentException("invalid MPF v1 inclusion proof");
        }
        return normalizeBranches(key, PoseidonMpfCodec.decode(proofWire), maxBranches);
    }

    /** Strictly verifies absence at an authenticated empty child and normalizes its branches. */
    public static PoseidonMpfBranchWitness emptyNonInclusion(
            byte[] root, byte[] key, byte[] proofWire, int maxBranches) {
        if (!PoseidonMpfReference.excluding(root, key, proofWire)) {
            throw new IllegalArgumentException("invalid MPF v1 non-inclusion proof");
        }
        return normalizeBranches(key, PoseidonMpfCodec.decode(proofWire), maxBranches);
    }

    static PoseidonMpfBranchWitness normalizeBranches(
            byte[] key, List<PoseidonMpfCodec.Step> steps, int maxBranches) {
        requireBound(maxBranches);
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(steps, "steps");
        if (steps.size() > maxBranches) {
            throw new IllegalArgumentException(
                    "proof has " + steps.size() + " branches, exceeding bound " + maxBranches);
        }
        for (int index = 0; index < steps.size(); index++) {
            if (steps.get(index).kind() != PoseidonMpfCodec.KIND_BRANCH) {
                throw new IllegalArgumentException(
                        "expected only BranchSteps, found kind " + steps.get(index).kind()
                                + " at index " + index);
            }
        }

        int[] path = PoseidonMpfHash.digestToNibbles(PoseidonMpfHashFunction.INSTANCE.digest(key));
        var keyPath = new ArrayList<BigInteger>(path.length);
        for (int nibble : path) keyPath.add(BigInteger.valueOf(nibble));
        var skip = new ArrayList<BigInteger>(maxBranches);
        var siblings = new ArrayList<List<BigInteger>>(maxBranches);
        var valid = new ArrayList<BigInteger>(maxBranches);
        for (PoseidonMpfCodec.Step step : steps) {
            skip.add(BigInteger.valueOf(step.skip()));
            if (step.neighbors().size() != 4) {
                throw new IllegalArgumentException("BranchStep must contain four sibling hashes");
            }
            siblings.add(List.copyOf(step.neighbors()));
            valid.add(BigInteger.ONE);
        }
        while (skip.size() < maxBranches) {
            skip.add(BigInteger.ZERO);
            siblings.add(Collections.nCopies(4, BigInteger.ZERO));
            valid.add(BigInteger.ZERO);
        }
        return new PoseidonMpfBranchWitness(keyPath, skip, siblings, valid, steps.size());
    }

    static void requireBound(int maxBranches) {
        if (maxBranches < 0 || maxBranches > PoseidonMpfCodec.MAX_PROOF_STEPS) {
            throw new IllegalArgumentException(
                    "maxBranches must be in [0, " + PoseidonMpfCodec.MAX_PROOF_STEPS + "]");
        }
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        return putInto(inputs, DEFAULT_NAMES);
    }

    public ZkInputMap putInto(ZkInputMap inputs, Names names) {
        Objects.requireNonNull(inputs, "inputs");
        Objects.requireNonNull(names, "names");
        return inputs.putArray(names.keyPath(), keyPath)
                .putArray(names.skip(), skip)
                .putNestedArray(names.siblings(), siblings)
                .putArray(names.valid(), valid);
    }

    public List<BigInteger> keyPath() { return keyPath; }
    public List<BigInteger> skip() { return skip; }
    public List<List<BigInteger>> siblings() { return siblings; }
    public List<BigInteger> valid() { return valid; }
    public int branchCount() { return branchCount; }
    public int maxBranches() { return skip.size(); }

    public record Names(String keyPath, String skip, String siblings, String valid) {
        public Names {
            requireName(keyPath, "keyPath");
            requireName(skip, "skip");
            requireName(siblings, "siblings");
            requireName(valid, "valid");
        }

        private static void requireName(String value, String name) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(name + " signal name must not be blank");
            }
        }
    }

    private static List<BigInteger> copyFlat(List<BigInteger> values, String name) {
        Objects.requireNonNull(values, name);
        for (int index = 0; index < values.size(); index++) {
            Objects.requireNonNull(values.get(index), name + "[" + index + "]");
        }
        return List.copyOf(values);
    }
}
