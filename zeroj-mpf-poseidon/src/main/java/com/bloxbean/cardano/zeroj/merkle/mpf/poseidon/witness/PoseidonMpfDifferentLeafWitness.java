package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.witness;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfReference;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/** Normalized, strictly verified MPF different-leaf non-inclusion witness. */
public record PoseidonMpfDifferentLeafWitness(
        PoseidonMpfBranchWitness branches,
        BigInteger terminalSkip,
        List<BigInteger> conflictingLeafPath,
        BigInteger conflictingValueCommitment) {

    public PoseidonMpfDifferentLeafWitness {
        Objects.requireNonNull(branches, "branches");
        Objects.requireNonNull(terminalSkip, "terminalSkip");
        conflictingLeafPath = List.copyOf(
                Objects.requireNonNull(conflictingLeafPath, "conflictingLeafPath"));
        if (conflictingLeafPath.size() != 64) {
            throw new IllegalArgumentException("conflictingLeafPath must contain 64 nibbles");
        }
        Objects.requireNonNull(conflictingValueCommitment, "conflictingValueCommitment");
    }

    public static PoseidonMpfDifferentLeafWitness nonInclusion(
            byte[] root, byte[] queryKey, byte[] proofWire, int maxBranches) {
        if (!PoseidonMpfReference.excluding(root, queryKey, proofWire)) {
            throw new IllegalArgumentException("invalid MPF v1 different-leaf proof");
        }
        List<PoseidonMpfCodec.Step> steps = PoseidonMpfCodec.decode(proofWire);
        if (steps.isEmpty() || steps.getLast().kind() != PoseidonMpfCodec.KIND_LEAF) {
            throw new IllegalArgumentException("proof does not terminate in a LeafStep");
        }
        PoseidonMpfCodec.Step leaf = steps.getLast();
        PoseidonMpfBranchWitness branches = PoseidonMpfBranchWitness.normalizeBranches(
                queryKey, steps.subList(0, steps.size() - 1), maxBranches);
        if (leaf.leafKeyPath().size() != 64) {
            throw new IllegalArgumentException("LeafStep must contain a complete 64-nibble key path");
        }
        return new PoseidonMpfDifferentLeafWitness(
                branches,
                BigInteger.valueOf(leaf.skip()),
                leaf.leafKeyPath(),
                leaf.leafValueDigest());
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        return branches.putInto(inputs)
                .put("mpf_terminal_skip", terminalSkip)
                .putArray("mpf_conflicting_leaf_path", conflictingLeafPath)
                .put("mpf_conflicting_value", conflictingValueCommitment);
    }
}
