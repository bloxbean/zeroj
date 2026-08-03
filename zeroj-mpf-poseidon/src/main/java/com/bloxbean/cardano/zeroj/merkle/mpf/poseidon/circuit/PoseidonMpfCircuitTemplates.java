package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfCodec;

/** Conservative standalone templates for the MPF v1 operation gadgets. */
public final class PoseidonMpfCircuitTemplates {
    public static final String ROOT = "root";
    public static final String OLD_ROOT = "oldRoot";
    public static final String NEW_ROOT = "newRoot";
    public static final String VALUE = "value_commitment";
    public static final String OLD_VALUE = "old_value_commitment";
    public static final String NEW_VALUE = "new_value_commitment";
    public static final String KEY_PATH = "key_path";
    public static final String BRANCH_SKIP = "mpf_branch_skip";
    public static final String BRANCH_SIBLING = "mpf_branch_sibling";
    public static final String BRANCH_VALID = "mpf_branch_valid";
    public static final String TERMINAL_SKIP = "mpf_terminal_skip";
    public static final String CONFLICTING_PATH = "mpf_conflicting_leaf_path";
    public static final String CONFLICTING_VALUE = "mpf_conflicting_value";

    private PoseidonMpfCircuitTemplates() {}

    /** Canonical MPF v1 inclusion template for CCL-generated branch paths. */
    public static CircuitBuilder inclusion(int maxBranches) {
        requireBound(maxBranches);
        CircuitBuilder circuit = CircuitBuilder.create(templateId("inclusion", maxBranches, 1))
                .publicVar(ROOT)
                .secretVar(VALUE);
        declareBranchInputs(circuit, maxBranches);
        return circuit.defineSignals(c -> ZkMpfInclusion.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c), ZkField.secret(c, VALUE), ZkField.publicInput(c, ROOT),
                branchProof(c, maxBranches)));
    }

    /**
     * Reference/migration template retaining the historical full proof union. New applications
     * should use {@link #inclusion(int)}. MPF's 64-nibble path has exactly two 32-nibble prefix
     * chunks, so there is intentionally no caller-controlled allocation bound.
     */
    public static CircuitBuilder fullSemanticsInclusion(int maxSteps) {
        requireBound(maxSteps);
        int maxForkPrefixChunks = maxSteps == 0 ? 0 : 2;
        CircuitBuilder circuit = CircuitBuilder.create(
                        templateId("full-semantics-inclusion", maxSteps, 1))
                .publicVar(ROOT)
                .secretVar(VALUE);
        declareGeneralProofInputs(circuit, maxSteps, maxForkPrefixChunks);
        return circuit.defineSignals(c -> ZkMpfInclusion.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c), ZkField.secret(c, VALUE), ZkField.publicInput(c, ROOT),
                generalProof(c, maxSteps, maxForkPrefixChunks)));
    }

    public static CircuitBuilder nonInclusionEmpty(int maxBranches) {
        requireBound(maxBranches);
        CircuitBuilder circuit = CircuitBuilder.create(
                templateId("non-inclusion-empty", maxBranches, 1)).publicVar(ROOT);
        declareBranchInputs(circuit, maxBranches);
        return circuit.defineSignals(c -> ZkMpfNonInclusionEmpty.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c), ZkField.publicInput(c, ROOT), branchProof(c, maxBranches)));
    }

    public static CircuitBuilder nonInclusionDifferentLeaf(int maxBranches) {
        requireBound(maxBranches);
        CircuitBuilder circuit = CircuitBuilder.create(
                templateId("non-inclusion-different-leaf", maxBranches, 1))
                .publicVar(ROOT)
                .secretVar(TERMINAL_SKIP)
                .secretVar(CONFLICTING_VALUE);
        declareBranchInputs(circuit, maxBranches);
        declareArray(circuit, CONFLICTING_PATH, ZkMpf.KEY_PATH_NIBBLES);
        return circuit.defineSignals(c -> ZkMpfNonInclusionDifferentLeaf.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c),
                ZkArray.secretUInts(c, CONFLICTING_PATH, ZkMpf.KEY_PATH_NIBBLES, 4),
                ZkField.secret(c, CONFLICTING_VALUE),
                ZkUInt.secret(c, TERMINAL_SKIP, 8),
                ZkField.publicInput(c, ROOT),
                branchProof(c, maxBranches)));
    }

    public static CircuitBuilder valueUpdate(int maxBranches) {
        requireBound(maxBranches);
        CircuitBuilder circuit = CircuitBuilder.create(
                        templateId("value-update", maxBranches, 2))
                .publicVar(OLD_ROOT)
                .publicVar(NEW_ROOT)
                .secretVar(OLD_VALUE)
                .secretVar(NEW_VALUE);
        declareBranchInputs(circuit, maxBranches);
        return circuit.defineSignals(c -> ZkMpfValueUpdate.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c), ZkField.secret(c, OLD_VALUE), ZkField.secret(c, NEW_VALUE),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                branchProof(c, maxBranches)));
    }

    public static CircuitBuilder insertEmpty(int maxBranches) {
        requireBound(maxBranches);
        CircuitBuilder circuit = CircuitBuilder.create(
                        templateId("insert-empty", maxBranches, 2))
                .publicVar(OLD_ROOT)
                .publicVar(NEW_ROOT)
                .secretVar(VALUE);
        declareBranchInputs(circuit, maxBranches);
        return circuit.defineSignals(c -> ZkMpfInsertEmpty.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c), ZkField.secret(c, VALUE),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                branchProof(c, maxBranches)));
    }

    public static CircuitBuilder insertDifferentLeaf(int maxBranches) {
        requireBound(maxBranches);
        CircuitBuilder circuit = CircuitBuilder.create(
                        templateId("insert-different-leaf", maxBranches, 2))
                .publicVar(OLD_ROOT)
                .publicVar(NEW_ROOT)
                .secretVar(VALUE)
                .secretVar(TERMINAL_SKIP)
                .secretVar(CONFLICTING_VALUE);
        declareBranchInputs(circuit, maxBranches);
        declareArray(circuit, CONFLICTING_PATH, ZkMpf.KEY_PATH_NIBBLES);
        return circuit.defineSignals(c -> ZkMpfInsertDifferentLeaf.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                keyPath(c), ZkField.secret(c, VALUE),
                ZkArray.secretUInts(c, CONFLICTING_PATH, ZkMpf.KEY_PATH_NIBBLES, 4),
                ZkField.secret(c, CONFLICTING_VALUE), ZkUInt.secret(c, TERMINAL_SKIP, 8),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                branchProof(c, maxBranches)));
    }

    static ZkMpfBranchProof branchProof(SignalBuilder signals, int maxBranches) {
        return ZkMpfBranchProof.fromArrays(
                ZkArray.secretUInts(signals, BRANCH_SKIP, maxBranches, 8),
                ZkArray.secretFieldMatrix(signals, BRANCH_SIBLING, maxBranches, 4),
                ZkArray.secretBools(signals, BRANCH_VALID, maxBranches));
    }

    static ZkMpfProof generalProof(
            SignalBuilder c, int maxSteps, int maxForkPrefixChunks) {
        return ZkMpfProof.fromArrays(
                ZkArray.secretUInts(c, "mpf_kind", maxSteps, 2),
                ZkArray.secretUInts(c, "mpf_skip", maxSteps, 8),
                ZkArray.secretFieldMatrix(c, "mpf_neighbor", maxSteps, 4),
                ZkArray.secretUInts(c, "mpf_neighbor_nibble", maxSteps, 4),
                ZkArray.secretUInts(c, "mpf_fork_prefix_length", maxSteps, 8),
                ZkArray.secretFieldMatrix(c, "mpf_fork_prefix", maxSteps, maxForkPrefixChunks),
                ZkArray.secretFields(c, "mpf_fork_root", maxSteps),
                ZkArray.secretUIntMatrix(c, "mpf_leaf_key_path", maxSteps,
                        ZkMpf.KEY_PATH_NIBBLES, 4),
                ZkArray.secretFields(c, "mpf_leaf_value_digest", maxSteps),
                ZkArray.secretBools(c, "mpf_valid", maxSteps));
    }

    static ZkArray<ZkUInt> keyPath(SignalBuilder signals) {
        return ZkArray.secretUInts(signals, KEY_PATH, ZkMpf.KEY_PATH_NIBBLES, 4);
    }

    static void declareBranchInputs(CircuitBuilder circuit, int maxBranches) {
        declareArray(circuit, KEY_PATH, ZkMpf.KEY_PATH_NIBBLES);
        declareArray(circuit, BRANCH_SKIP, maxBranches);
        declareMatrix(circuit, BRANCH_SIBLING, maxBranches, 4);
        declareArray(circuit, BRANCH_VALID, maxBranches);
    }

    static void declareGeneralProofInputs(
            CircuitBuilder circuit, int maxSteps, int maxForkPrefixChunks) {
        declareArray(circuit, KEY_PATH, ZkMpf.KEY_PATH_NIBBLES);
        declareArray(circuit, "mpf_kind", maxSteps);
        declareArray(circuit, "mpf_skip", maxSteps);
        declareMatrix(circuit, "mpf_neighbor", maxSteps, 4);
        declareArray(circuit, "mpf_neighbor_nibble", maxSteps);
        declareArray(circuit, "mpf_fork_prefix_length", maxSteps);
        declareMatrix(circuit, "mpf_fork_prefix", maxSteps, maxForkPrefixChunks);
        declareArray(circuit, "mpf_fork_root", maxSteps);
        declareMatrix(circuit, "mpf_leaf_key_path", maxSteps, ZkMpf.KEY_PATH_NIBBLES);
        declareArray(circuit, "mpf_leaf_value_digest", maxSteps);
        declareArray(circuit, "mpf_valid", maxSteps);
    }

    static void declareArray(CircuitBuilder circuit, String name, int size) {
        for (int index = 0; index < size; index++) circuit.secretVar(name + "_" + index);
    }

    static void declareMatrix(CircuitBuilder circuit, String name, int rows, int columns) {
        for (int row = 0; row < rows; row++) {
            for (int column = 0; column < columns; column++) {
                circuit.secretVar(name + "_" + row + "_" + column);
            }
        }
    }

    static void requireBound(int maxBranches) {
        if (maxBranches < 0 || maxBranches > PoseidonMpfCodec.MAX_PROOF_STEPS) {
            throw new IllegalArgumentException(
                    "maxBranches must be in [0, " + PoseidonMpfCodec.MAX_PROOF_STEPS + "]");
        }
    }

    private static String templateId(String operation, int maxBranches, int publicInputs) {
        return "zeroj-mpf-v1-" + operation + "-s" + maxBranches + "-p" + publicInputs;
    }
}
