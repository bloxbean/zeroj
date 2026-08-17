package com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.Signal;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkValue;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Minimal normalized MPF path containing only authenticated BranchSteps. */
public final class ZkMpfBranchProof implements ZkValue {
    public static final int SIBLINGS_PER_BRANCH = 4;

    private final ZkArray<ZkUInt> skip;
    private final ZkArray<ZkArray<ZkField>> siblings;
    private final ZkArray<ZkBool> valid;

    private ZkMpfBranchProof(
            ZkArray<ZkUInt> skip,
            ZkArray<ZkArray<ZkField>> siblings,
            ZkArray<ZkBool> valid) {
        this.skip = Objects.requireNonNull(skip, "skip");
        this.siblings = Objects.requireNonNull(siblings, "siblings");
        this.valid = Objects.requireNonNull(valid, "valid");
        if (skip.size() != siblings.size() || skip.size() != valid.size()) {
            throw new IllegalArgumentException("skip, siblings, and valid arrays must have equal sizes");
        }
        for (int index = 0; index < skip.size(); index++) {
            if (skip.get(index).bits() != 8) {
                throw new IllegalArgumentException("skip[" + index + "] must be an 8-bit ZkUInt");
            }
            if (siblings.get(index).size() != SIBLINGS_PER_BRANCH) {
                throw new IllegalArgumentException(
                        "siblings[" + index + "] must contain exactly four fields");
            }
        }
    }

    public static ZkMpfBranchProof fromArrays(
            ZkArray<ZkUInt> skip,
            ZkArray<ZkArray<ZkField>> siblings,
            ZkArray<ZkBool> valid) {
        return new ZkMpfBranchProof(skip, siblings, valid);
    }

    public int maxSteps() { return skip.size(); }
    public ZkArray<ZkUInt> skip() { return skip; }
    public ZkArray<ZkArray<ZkField>> siblings() { return siblings; }
    public ZkArray<ZkBool> valid() { return valid; }

    @Override
    public List<Signal> signals() {
        var output = new ArrayList<Signal>();
        output.addAll(skip.signals());
        output.addAll(siblings.signals());
        output.addAll(valid.signals());
        return List.copyOf(output);
    }

    @Override
    public void assertWellFormed() {
        skip.assertWellFormed();
        siblings.assertWellFormed();
        valid.assertWellFormed();
    }
}
