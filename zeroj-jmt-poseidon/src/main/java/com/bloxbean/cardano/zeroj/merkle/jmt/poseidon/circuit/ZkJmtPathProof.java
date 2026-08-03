package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit;

import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;

import java.util.Objects;

/** Fixed-bound normalized JMT path with prefix-valid rows and canonical zero padding. */
public final class ZkJmtPathProof {
    private final ZkArray<ZkArray<ZkField>> siblings;
    private final ZkArray<ZkBool> valid;

    private ZkJmtPathProof(
            ZkArray<ZkArray<ZkField>> siblings,
            ZkArray<ZkBool> valid) {
        this.siblings = Objects.requireNonNull(siblings, "siblings");
        this.valid = Objects.requireNonNull(valid, "valid");
        if (siblings.size() != valid.size()) {
            throw new IllegalArgumentException("JMT sibling and validity rows must have equal size");
        }
        if (valid.size() > PoseidonJmtProfile.KEY_NIBBLES) {
            throw new IllegalArgumentException("JMT path bound cannot exceed 64 levels");
        }
        for (int level = 0; level < siblings.size(); level++) {
            if (siblings.get(level).size() != PoseidonJmtProfile.BRANCH_LEVELS) {
                throw new IllegalArgumentException("each JMT level requires four binary siblings");
            }
        }
    }

    public static ZkJmtPathProof fromArrays(
            ZkArray<ZkArray<ZkField>> siblings,
            ZkArray<ZkBool> valid) {
        return new ZkJmtPathProof(siblings, valid);
    }

    void assertWellFormed(ZkContext zk) {
        for (int level = 0; level < maxLevels(); level++) {
            ZkBool rowValid = valid.get(level);
            rowValid.assertWellFormed();
            if (level + 1 < maxLevels()) {
                rowValid.not().and(valid.get(level + 1)).assertFalse();
            }
            for (ZkField sibling : siblings.get(level).values()) {
                rowValid.not().and(sibling.isEqual(zk.constant(0)).not()).assertFalse();
            }
        }
    }

    public ZkArray<ZkArray<ZkField>> siblings() { return siblings; }
    public ZkArray<ZkBool> valid() { return valid; }
    public int maxLevels() { return valid.size(); }
}
