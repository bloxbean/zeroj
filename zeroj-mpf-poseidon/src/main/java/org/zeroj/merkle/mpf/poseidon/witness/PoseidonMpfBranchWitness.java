package org.zeroj.merkle.mpf.poseidon.witness;

import com.bloxbean.cardano.vds.core.NibblePath;
import org.zeroj.circuit.annotation.ZkInputMap;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCommitmentScheme;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfHashFunction;
import org.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfReference;
import org.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Canonical fixed-bound witness for an MPF branch path. Compact 2-child CCL
 * ForkStep and non-terminal LeafStep roll-ups are expanded to their exact
 * 4-sibling binary-Merkle branch form so the circuit representation remains
 * uniform and fixed-shape. Proof-form selection happens in the factory method,
 * before circuit input is created; it is never represented by a witness flag.
 */
public final class PoseidonMpfBranchWitness {
    public static final Names DEFAULT_NAMES =
            new Names("key_path", "mpf_branch_skip", "mpf_branch_sibling", "mpf_branch_valid");

    private static final PoseidonMpfCommitmentScheme STATELESS_COMMITMENTS =
            new PoseidonMpfCommitmentScheme(PoseidonParamsBLS12_381T3.INSTANCE, 0);
    private static final byte[] EMPTY_L0 = new byte[PoseidonMpfHash.DIGEST_LENGTH];
    private static final byte[] EMPTY_L1 =
            PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, EMPTY_L0, EMPTY_L0);
    private static final byte[] EMPTY_L2 =
            PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, EMPTY_L1, EMPTY_L1);
    private static final byte[] EMPTY_L3 =
            PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, EMPTY_L2, EMPTY_L2);

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

    /** Strictly verifies and normalizes an inclusion proof into fixed-shape branch steps. */
    public static PoseidonMpfBranchWitness inclusion(
            byte[] root, byte[] key, byte[] value, byte[] proofWire, int maxBranches) {
        if (!PoseidonMpfReference.including(root, key, value, proofWire)) {
            throw new IllegalArgumentException("invalid MPF v1 inclusion proof");
        }
        return normalizeBranches(key, PoseidonMpfCodec.decode(proofWire), maxBranches, false);
    }

    /** Strictly verifies absence at an authenticated empty child and normalizes its branches. */
    public static PoseidonMpfBranchWitness emptyNonInclusion(
            byte[] root, byte[] key, byte[] proofWire, int maxBranches) {
        if (!PoseidonMpfReference.excluding(root, key, proofWire)) {
            throw new IllegalArgumentException("invalid MPF v1 non-inclusion proof");
        }
        return normalizeBranches(key, PoseidonMpfCodec.decode(proofWire), maxBranches, true);
    }

    static PoseidonMpfBranchWitness normalizeBranches(
            byte[] key, List<PoseidonMpfCodec.Step> steps, int maxBranches) {
        return normalizeBranches(key, steps, maxBranches, false);
    }

    static PoseidonMpfBranchWitness normalizeBranches(
            byte[] key,
            List<PoseidonMpfCodec.Step> steps,
            int maxBranches,
            boolean requireFinalBranch) {
        requireBound(maxBranches);
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(steps, "steps");
        if (steps.size() > maxBranches) {
            throw new IllegalArgumentException(
                    "proof has " + steps.size() + " branches, exceeding bound " + maxBranches);
        }
        if (requireFinalBranch && !steps.isEmpty()
                && steps.getLast().kind() != PoseidonMpfCodec.KIND_BRANCH) {
            throw new IllegalArgumentException(
                    "empty non-inclusion proof must terminate in a BranchStep, found kind "
                            + steps.getLast().kind());
        }

        int[] path = PoseidonMpfHash.digestToNibbles(PoseidonMpfHashFunction.INSTANCE.digest(key));
        var keyPath = new ArrayList<BigInteger>(path.length);
        for (int nibble : path) keyPath.add(BigInteger.valueOf(nibble));
        var skip = new ArrayList<BigInteger>(maxBranches);
        var siblings = new ArrayList<List<BigInteger>>(maxBranches);
        var valid = new ArrayList<BigInteger>(maxBranches);
        int cursor = 0;
        for (int index = 0; index < steps.size(); index++) {
            PoseidonMpfCodec.Step step = steps.get(index);
            int stepSkip = step.skip();
            int branchPos = cursor + stepSkip;
            if (stepSkip < 0 || branchPos >= path.length) {
                throw new IllegalArgumentException("proof step skips past the end of the path");
            }
            int meNibble = path[branchPos];
            List<BigInteger> stepSiblings = switch (step.kind()) {
                case PoseidonMpfCodec.KIND_BRANCH -> {
                    if (step.neighbors().size() != 4) {
                        throw new IllegalArgumentException("BranchStep must contain four sibling hashes");
                    }
                    yield List.copyOf(step.neighbors());
                }
                case PoseidonMpfCodec.KIND_FORK -> normalizeForkStep(step, meNibble);
                case PoseidonMpfCodec.KIND_LEAF -> normalizeLeafStep(step, path, branchPos, meNibble);
                default -> throw new IllegalArgumentException(
                        "unsupported MPF step kind " + step.kind() + " at index " + index);
            };
            skip.add(BigInteger.valueOf(stepSkip));
            siblings.add(stepSiblings);
            valid.add(BigInteger.ONE);
            cursor = branchPos + 1;
        }
        while (skip.size() < maxBranches) {
            skip.add(BigInteger.ZERO);
            siblings.add(Collections.nCopies(4, BigInteger.ZERO));
            valid.add(BigInteger.ZERO);
        }
        return new PoseidonMpfBranchWitness(keyPath, skip, siblings, valid, steps.size());
    }

    private static List<BigInteger> normalizeForkStep(PoseidonMpfCodec.Step step, int meNibble) {
        int otherNibble = step.neighborNibble();
        if (otherNibble == meNibble) {
            throw new IllegalArgumentException("ForkStep neighbor nibble equals path nibble");
        }
        byte[] prefixBytes = step.forkPrefixBytes();
        byte[] forkRootBytes = PoseidonMpfHash.toDigestBytes(step.forkRoot());
        byte[] combined = new byte[prefixBytes.length + forkRootBytes.length];
        System.arraycopy(prefixBytes, 0, combined, 0, prefixBytes.length);
        System.arraycopy(forkRootBytes, 0, combined, prefixBytes.length, forkRootBytes.length);
        byte[] siblingHash = PoseidonMpfHashFunction.INSTANCE.digest(combined);
        return sparseSiblings(meNibble, otherNibble, siblingHash);
    }

    private static List<BigInteger> normalizeLeafStep(
            PoseidonMpfCodec.Step step, int[] path, int branchPos, int meNibble) {
        List<BigInteger> leafKeyPath = step.leafKeyPath();
        if (leafKeyPath.size() != path.length) {
            throw new IllegalArgumentException("LeafStep must contain a complete 64-nibble key path");
        }
        int[] leafNibbles = new int[path.length];
        for (int i = 0; i < path.length; i++) {
            int nibble = leafKeyPath.get(i).intValueExact();
            if (nibble < 0 || nibble > 15) {
                throw new IllegalArgumentException("LeafStep nibble out of range: " + nibble);
            }
            leafNibbles[i] = nibble;
        }
        for (int i = 0; i < branchPos; i++) {
            if (leafNibbles[i] != path[i]) {
                throw new IllegalArgumentException("LeafStep prefix does not match key path");
            }
        }
        int otherNibble = leafNibbles[branchPos];
        if (otherNibble == meNibble) {
            throw new IllegalArgumentException("LeafStep neighbor nibble equals path nibble");
        }
        byte[] siblingHash = STATELESS_COMMITMENTS.commitLeaf(
                NibblePath.fromRange(leafNibbles, branchPos + 1, leafNibbles.length - branchPos - 1),
                PoseidonMpfHash.toDigestBytes(step.leafValueDigest()));
        return sparseSiblings(meNibble, otherNibble, siblingHash);
    }

    private static List<BigInteger> sparseSiblings(int meNibble, int otherNibble, byte[] otherHash) {
        byte[] n3 = ((meNibble ^ 1) == otherNibble) ? otherHash : EMPTY_L0;

        int idx1 = otherNibble >>> 1;
        byte[] val1 = (otherNibble & 1) == 0
                ? PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, otherHash, EMPTY_L0)
                : PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, EMPTY_L0, otherHash);
        byte[] n2 = (((meNibble >>> 1) ^ 1) == idx1) ? val1 : EMPTY_L1;

        int idx2 = otherNibble >>> 2;
        byte[] val2 = (idx1 & 1) == 0
                ? PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, val1, EMPTY_L1)
                : PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, EMPTY_L1, val1);
        byte[] n1 = (((meNibble >>> 2) ^ 1) == idx2) ? val2 : EMPTY_L2;

        int idx3 = otherNibble >>> 3;
        byte[] val3 = (idx2 & 1) == 0
                ? PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, val2, EMPTY_L2)
                : PoseidonMpfHash.digestPair(PoseidonParamsBLS12_381T3.INSTANCE, EMPTY_L2, val2);
        byte[] n0 = (((meNibble >>> 3) ^ 1) == idx3) ? val3 : EMPTY_L3;

        return List.of(
                PoseidonMpfHash.fieldFromDigestBytes(n0),
                PoseidonMpfHash.fieldFromDigestBytes(n1),
                PoseidonMpfHash.fieldFromDigestBytes(n2),
                PoseidonMpfHash.fieldFromDigestBytes(n3));
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
