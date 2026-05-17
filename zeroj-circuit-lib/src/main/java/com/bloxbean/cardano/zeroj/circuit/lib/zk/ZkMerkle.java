package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.lib.SignalMerkle;

import java.util.Objects;

/**
 * Symbolic fixed-depth Merkle helpers for annotation-based circuits.
 */
public final class ZkMerkle {

    private ZkMerkle() {}

    public enum HashType {
        MIMC,
        POSEIDON
    }

    @FunctionalInterface
    public interface HashFn {
        ZkField hash(ZkContext zk, ZkField left, ZkField right);
    }

    public static ZkField computeRoot(
            ZkContext zk,
            ZkField leaf,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashType hashType) {
        Objects.requireNonNull(hashType, "hashType");
        return switch (hashType) {
            case MIMC -> computeRoot(zk, leaf, siblings, pathBits, ZkMiMC::hash);
            case POSEIDON -> computeRoot(zk, leaf, siblings, pathBits, ZkPoseidon::hash);
        };
    }

    public static ZkField computeRoot(
            ZkContext zk,
            ZkField leaf,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashFn hashFn) {
        validateInputs(zk, leaf, siblings, pathBits, hashFn);

        Signal root = SignalMerkle.computeRoot(
                zk.builder(),
                leaf.signal(),
                fieldSignals(siblings),
                boolSignals(pathBits),
                (c, left, right) -> {
                    ZkField hashed = hashFn.hash(zk, ZkField.wrap(zk, left), ZkField.wrap(zk, right));
                    zk.requireSignal(hashed.signal());
                    return hashed.signal();
                });
        return ZkField.wrap(zk, root);
    }

    public static void verify(
            ZkContext zk,
            ZkField leaf,
            ZkField root,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashType hashType) {
        requireRoot(zk, root);
        computeRoot(zk, leaf, siblings, pathBits, hashType).assertEqual(root);
    }

    public static void verifyProof(
            ZkContext zk,
            ZkField leaf,
            ZkField root,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashType hashType) {
        verify(zk, leaf, root, siblings, pathBits, hashType);
    }

    public static void verify(
            ZkContext zk,
            ZkField leaf,
            ZkField root,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashFn hashFn) {
        requireRoot(zk, root);
        computeRoot(zk, leaf, siblings, pathBits, hashFn).assertEqual(root);
    }

    public static void verifyProof(
            ZkContext zk,
            ZkField leaf,
            ZkField root,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashFn hashFn) {
        verify(zk, leaf, root, siblings, pathBits, hashFn);
    }

    public static ZkBool isMember(
            ZkContext zk,
            ZkField leaf,
            ZkField root,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashType hashType) {
        requireRoot(zk, root);
        return computeRoot(zk, leaf, siblings, pathBits, hashType).isEqual(root);
    }

    public static ZkBool isMember(
            ZkContext zk,
            ZkField leaf,
            ZkField root,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashFn hashFn) {
        requireRoot(zk, root);
        return computeRoot(zk, leaf, siblings, pathBits, hashFn).isEqual(root);
    }

    private static void validateInputs(
            ZkContext zk,
            ZkField leaf,
            ZkArray<ZkField> siblings,
            ZkArray<ZkBool> pathBits,
            HashFn hashFn) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(leaf, "leaf");
        Objects.requireNonNull(siblings, "siblings");
        Objects.requireNonNull(pathBits, "pathBits");
        Objects.requireNonNull(hashFn, "hashFn");

        if (siblings.size() != pathBits.size()) {
            throw new IllegalArgumentException("siblings and pathBits must have equal length");
        }

        zk.requireSignal(leaf.signal());
        for (ZkField sibling : siblings.values()) {
            zk.requireSignal(sibling.signal());
        }
        for (ZkBool pathBit : pathBits.values()) {
            zk.requireSignal(pathBit.signal());
        }
    }

    private static void requireRoot(ZkContext zk, ZkField root) {
        Objects.requireNonNull(zk, "zk");
        Objects.requireNonNull(root, "root");
        zk.requireSignal(root.signal());
    }

    private static Signal[] fieldSignals(ZkArray<ZkField> values) {
        Signal[] signals = new Signal[values.size()];
        for (int i = 0; i < values.size(); i++) {
            signals[i] = values.get(i).signal();
        }
        return signals;
    }

    private static Signal[] boolSignals(ZkArray<ZkBool> values) {
        Signal[] signals = new Signal[values.size()];
        for (int i = 0; i < values.size(); i++) {
            signals[i] = values.get(i).signal();
        }
        return signals;
    }
}
