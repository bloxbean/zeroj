package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.SignalBuilder;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

/** Conservative standalone public-input schemas for Poseidon JMT v1 primitives. */
public final class PoseidonJmtCircuitTemplates {
    public static final String ROOT = "root";
    public static final String OLD_ROOT = "oldRoot";
    public static final String NEW_ROOT = "newRoot";
    public static final String KEY_NIBBLE = "jmt_key_nibble";
    public static final String SIBLING = "jmt_sibling";
    public static final String VALID = "jmt_valid";
    public static final String VALUE_HASH = "jmt_value_hash";
    public static final String OLD_VALUE_HASH = "jmt_old_value_hash";
    public static final String NEW_VALUE_HASH = "jmt_new_value_hash";
    public static final String CONFLICTING_KEY_NIBBLE = "jmt_conflicting_key_nibble";
    public static final String CONFLICTING_VALUE_HASH = "jmt_conflicting_value_hash";
    public static final String TOMBSTONE_VALUE_HASH = "jmt_tombstone_value_hash";

    private PoseidonJmtCircuitTemplates() {}

    public static CircuitBuilder inclusion(int maxLevels) {
        CircuitBuilder circuit = base("inclusion", maxLevels, 1)
                .publicVar(ROOT).secretVar(VALUE_HASH);
        declarePath(circuit, maxLevels);
        return circuit.defineSignals(c -> ZkJmtInclusion.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), ZkField.secret(c, VALUE_HASH), ZkField.publicInput(c, ROOT),
                proof(c, maxLevels)));
    }

    public static CircuitBuilder nonInclusionEmpty(int maxLevels) {
        CircuitBuilder circuit = base("non-inclusion-empty", maxLevels, 1).publicVar(ROOT);
        declarePath(circuit, maxLevels);
        return circuit.defineSignals(c -> ZkJmtNonInclusionEmpty.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), ZkField.publicInput(c, ROOT), proof(c, maxLevels)));
    }

    public static CircuitBuilder nonInclusionDifferentLeaf(int maxLevels) {
        CircuitBuilder circuit = base("non-inclusion-different-leaf", maxLevels, 1)
                .publicVar(ROOT).secretVar(CONFLICTING_VALUE_HASH);
        declarePath(circuit, maxLevels);
        declareArray(circuit, CONFLICTING_KEY_NIBBLE, PoseidonJmtProfile.KEY_NIBBLES);
        return circuit.defineSignals(c -> ZkJmtNonInclusionDifferentLeaf.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), conflictingKey(c), ZkField.secret(c, CONFLICTING_VALUE_HASH),
                ZkField.publicInput(c, ROOT), proof(c, maxLevels)));
    }

    public static CircuitBuilder valueUpdate(int maxLevels) {
        CircuitBuilder circuit = base("value-update", maxLevels, 2)
                .publicVar(OLD_ROOT).publicVar(NEW_ROOT)
                .secretVar(OLD_VALUE_HASH).secretVar(NEW_VALUE_HASH);
        declarePath(circuit, maxLevels);
        return circuit.defineSignals(c -> ZkJmtValueUpdate.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), ZkField.secret(c, OLD_VALUE_HASH), ZkField.secret(c, NEW_VALUE_HASH),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                proof(c, maxLevels)));
    }

    public static CircuitBuilder insertEmpty(int maxLevels) {
        CircuitBuilder circuit = base("insert-empty", maxLevels, 2)
                .publicVar(OLD_ROOT).publicVar(NEW_ROOT).secretVar(VALUE_HASH);
        declarePath(circuit, maxLevels);
        return circuit.defineSignals(c -> ZkJmtInsertEmpty.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), ZkField.secret(c, VALUE_HASH),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                proof(c, maxLevels)));
    }

    public static CircuitBuilder insertDifferentLeaf(int maxLevels) {
        CircuitBuilder circuit = base("insert-different-leaf", maxLevels, 2)
                .publicVar(OLD_ROOT).publicVar(NEW_ROOT)
                .secretVar(VALUE_HASH).secretVar(CONFLICTING_VALUE_HASH);
        declarePath(circuit, maxLevels);
        declareArray(circuit, CONFLICTING_KEY_NIBBLE, PoseidonJmtProfile.KEY_NIBBLES);
        return circuit.defineSignals(c -> ZkJmtInsertDifferentLeaf.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), ZkField.secret(c, VALUE_HASH),
                conflictingKey(c), ZkField.secret(c, CONFLICTING_VALUE_HASH),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                proof(c, maxLevels)));
    }

    public static CircuitBuilder tombstoneUpdate(int maxLevels) {
        CircuitBuilder circuit = base("tombstone-update", maxLevels, 3)
                .publicVar(OLD_ROOT).publicVar(NEW_ROOT)
                .publicVar(TOMBSTONE_VALUE_HASH).secretVar(OLD_VALUE_HASH);
        declarePath(circuit, maxLevels);
        return circuit.defineSignals(c -> ZkJmtTombstoneUpdate.verify(
                new ZkContext(c), PoseidonParamsBLS12_381T3.INSTANCE,
                key(c), ZkField.secret(c, OLD_VALUE_HASH),
                ZkField.publicInput(c, TOMBSTONE_VALUE_HASH),
                ZkField.publicInput(c, OLD_ROOT), ZkField.publicInput(c, NEW_ROOT),
                proof(c, maxLevels)));
    }

    static ZkJmtPathProof proof(SignalBuilder c, int maxLevels) {
        return ZkJmtPathProof.fromArrays(
                ZkArray.secretFieldMatrix(c, SIBLING, maxLevels, PoseidonJmtProfile.BRANCH_LEVELS),
                ZkArray.secretBools(c, VALID, maxLevels));
    }

    static ZkArray<ZkUInt> key(SignalBuilder c) {
        return ZkArray.secretUInts(c, KEY_NIBBLE, PoseidonJmtProfile.KEY_NIBBLES, 4);
    }

    static ZkArray<ZkUInt> conflictingKey(SignalBuilder c) {
        return ZkArray.secretUInts(
                c, CONFLICTING_KEY_NIBBLE, PoseidonJmtProfile.KEY_NIBBLES, 4);
    }

    private static CircuitBuilder base(
            String operation, int maxLevels, int publicInputs) {
        requireBound(maxLevels);
        return CircuitBuilder.create("zeroj-jmt-v1-" + operation
                + "-s" + maxLevels + "-p" + publicInputs);
    }

    private static void declarePath(CircuitBuilder circuit, int maxLevels) {
        declareArray(circuit, KEY_NIBBLE, PoseidonJmtProfile.KEY_NIBBLES);
        declareMatrix(circuit, SIBLING, maxLevels, PoseidonJmtProfile.BRANCH_LEVELS);
        declareArray(circuit, VALID, maxLevels);
    }

    private static void requireBound(int maxLevels) {
        if (maxLevels < 0 || maxLevels > PoseidonJmtProfile.KEY_NIBBLES) {
            throw new IllegalArgumentException("maxLevels must be in [0, 64]");
        }
    }

    private static void declareArray(CircuitBuilder circuit, String name, int size) {
        for (int index = 0; index < size; index++) circuit.secretVar(name + "_" + index);
    }

    private static void declareMatrix(
            CircuitBuilder circuit, String name, int rows, int columns) {
        for (int row = 0; row < rows; row++) {
            for (int column = 0; column < columns; column++) {
                circuit.secretVar(name + "_" + row + "_" + column);
            }
        }
    }
}
