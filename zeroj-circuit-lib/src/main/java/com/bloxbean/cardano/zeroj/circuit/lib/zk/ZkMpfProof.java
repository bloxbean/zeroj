package com.bloxbean.cardano.zeroj.circuit.lib.zk;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Flattened symbolic MPF proof wrapper.
 *
 * <p>The annotation processor binds the individual arrays directly. This
 * wrapper gives circuit code one value object without requiring composite
 * symbolic-input support in generated code.
 */
public final class ZkMpfProof implements ZkValue {
    public static final int BRANCH_NEIGHBOR_COUNT = 4;
    public static final int KEY_PATH_NIBBLES = 64;

    private final ZkArray<ZkUInt> kind;
    private final ZkArray<ZkUInt> skip;
    private final ZkArray<ZkArray<ZkField>> neighbors;
    private final ZkArray<ZkUInt> neighborNibble;
    private final ZkArray<ZkUInt> forkPrefixLength;
    private final ZkArray<ZkArray<ZkField>> forkPrefixChunks;
    private final ZkArray<ZkField> forkRoot;
    private final ZkArray<ZkArray<ZkUInt>> leafKeyPath;
    private final ZkArray<ZkField> leafValueDigest;
    private final ZkArray<ZkBool> valid;

    private ZkMpfProof(
            ZkArray<ZkUInt> kind,
            ZkArray<ZkUInt> skip,
            ZkArray<ZkArray<ZkField>> neighbors,
            ZkArray<ZkUInt> neighborNibble,
            ZkArray<ZkUInt> forkPrefixLength,
            ZkArray<ZkArray<ZkField>> forkPrefixChunks,
            ZkArray<ZkField> forkRoot,
            ZkArray<ZkArray<ZkUInt>> leafKeyPath,
            ZkArray<ZkField> leafValueDigest,
            ZkArray<ZkBool> valid) {
        this.kind = Objects.requireNonNull(kind, "kind");
        this.skip = Objects.requireNonNull(skip, "skip");
        this.neighbors = Objects.requireNonNull(neighbors, "neighbors");
        this.neighborNibble = Objects.requireNonNull(neighborNibble, "neighborNibble");
        this.forkPrefixLength = Objects.requireNonNull(forkPrefixLength, "forkPrefixLength");
        this.forkPrefixChunks = Objects.requireNonNull(forkPrefixChunks, "forkPrefixChunks");
        this.forkRoot = Objects.requireNonNull(forkRoot, "forkRoot");
        this.leafKeyPath = Objects.requireNonNull(leafKeyPath, "leafKeyPath");
        this.leafValueDigest = Objects.requireNonNull(leafValueDigest, "leafValueDigest");
        this.valid = Objects.requireNonNull(valid, "valid");
        validateShape();
    }

    public static ZkMpfProof fromArrays(
            ZkArray<ZkUInt> kind,
            ZkArray<ZkUInt> skip,
            ZkArray<ZkArray<ZkField>> neighbors,
            ZkArray<ZkUInt> neighborNibble,
            ZkArray<ZkUInt> forkPrefixLength,
            ZkArray<ZkArray<ZkField>> forkPrefixChunks,
            ZkArray<ZkField> forkRoot,
            ZkArray<ZkArray<ZkUInt>> leafKeyPath,
            ZkArray<ZkField> leafValueDigest,
            ZkArray<ZkBool> valid) {
        return new ZkMpfProof(
                kind,
                skip,
                neighbors,
                neighborNibble,
                forkPrefixLength,
                forkPrefixChunks,
                forkRoot,
                leafKeyPath,
                leafValueDigest,
                valid);
    }

    public int maxSteps() {
        return kind.size();
    }

    public int maxForkPrefixChunks() {
        return forkPrefixChunks.size() == 0 ? 0 : forkPrefixChunks.get(0).size();
    }

    public ZkArray<ZkUInt> kind() {
        return kind;
    }

    public ZkArray<ZkUInt> skip() {
        return skip;
    }

    public ZkArray<ZkArray<ZkField>> neighbors() {
        return neighbors;
    }

    public ZkArray<ZkUInt> neighborNibble() {
        return neighborNibble;
    }

    public ZkArray<ZkUInt> forkPrefixLength() {
        return forkPrefixLength;
    }

    public ZkArray<ZkArray<ZkField>> forkPrefixChunks() {
        return forkPrefixChunks;
    }

    public ZkArray<ZkField> forkRoot() {
        return forkRoot;
    }

    public ZkArray<ZkArray<ZkUInt>> leafKeyPath() {
        return leafKeyPath;
    }

    public ZkArray<ZkField> leafValueDigest() {
        return leafValueDigest;
    }

    public ZkArray<ZkBool> valid() {
        return valid;
    }

    @Override
    public List<Signal> signals() {
        var signals = new ArrayList<Signal>();
        signals.addAll(kind.signals());
        signals.addAll(skip.signals());
        signals.addAll(neighbors.signals());
        signals.addAll(neighborNibble.signals());
        signals.addAll(forkPrefixLength.signals());
        signals.addAll(forkPrefixChunks.signals());
        signals.addAll(forkRoot.signals());
        signals.addAll(leafKeyPath.signals());
        signals.addAll(leafValueDigest.signals());
        signals.addAll(valid.signals());
        return List.copyOf(signals);
    }

    @Override
    public void assertWellFormed() {
        kind.assertWellFormed();
        skip.assertWellFormed();
        neighbors.assertWellFormed();
        neighborNibble.assertWellFormed();
        forkPrefixLength.assertWellFormed();
        forkPrefixChunks.assertWellFormed();
        forkRoot.assertWellFormed();
        leafKeyPath.assertWellFormed();
        leafValueDigest.assertWellFormed();
        valid.assertWellFormed();
    }

    private void validateShape() {
        int size = kind.size();
        requireSameSize("skip", skip.size(), size);
        requireSameSize("neighbors", neighbors.size(), size);
        requireSameSize("neighborNibble", neighborNibble.size(), size);
        requireSameSize("forkPrefixLength", forkPrefixLength.size(), size);
        requireSameSize("forkPrefixChunks", forkPrefixChunks.size(), size);
        requireSameSize("forkRoot", forkRoot.size(), size);
        requireSameSize("leafKeyPath", leafKeyPath.size(), size);
        requireSameSize("leafValueDigest", leafValueDigest.size(), size);
        requireSameSize("valid", valid.size(), size);

        requireUIntBits("kind", kind, 2);
        requireUIntBits("skip", skip, 8);
        requireUIntBits("neighborNibble", neighborNibble, 4);
        requireUIntBits("forkPrefixLength", forkPrefixLength, 8);

        Integer forkChunkCount = null;
        for (int i = 0; i < size; i++) {
            if (neighbors.get(i).size() != BRANCH_NEIGHBOR_COUNT) {
                throw new IllegalArgumentException(
                        "neighbors[" + i + "] must have size " + BRANCH_NEIGHBOR_COUNT
                                + ", got " + neighbors.get(i).size());
            }
            if (leafKeyPath.get(i).size() != KEY_PATH_NIBBLES) {
                throw new IllegalArgumentException(
                        "leafKeyPath[" + i + "] must have size " + KEY_PATH_NIBBLES
                                + ", got " + leafKeyPath.get(i).size());
            }
            requireUIntBits("leafKeyPath[" + i + "]", leafKeyPath.get(i), 4);
            int rowSize = forkPrefixChunks.get(i).size();
            if (forkChunkCount == null) {
                forkChunkCount = rowSize;
            } else if (forkChunkCount != rowSize) {
                throw new IllegalArgumentException("forkPrefixChunks must be rectangular");
            }
        }
        if (size > 0 && forkChunkCount != null && forkChunkCount < 2) {
            throw new IllegalArgumentException(
                    "forkPrefixChunks inner size must be at least 2 when maxSteps > 0");
        }
    }

    private static void requireUIntBits(String name, ZkArray<ZkUInt> values, int expectedBits) {
        for (int i = 0; i < values.size(); i++) {
            int actualBits = values.get(i).bits();
            if (actualBits != expectedBits) {
                throw new IllegalArgumentException(
                        name + "[" + i + "] must be a " + expectedBits + "-bit ZkUInt, got "
                                + actualBits + " bits");
            }
        }
    }

    private static void requireSameSize(String name, int actual, int expected) {
        if (actual != expected) {
            throw new IllegalArgumentException(
                    name + " must have size " + expected + ", got " + actual);
        }
    }
}
