package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.CircuitParam;
import com.bloxbean.cardano.zeroj.circuit.annotation.FixedSize;
import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkArray;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMerkle;

@ZKCircuit(name = "annotation-merkle", nameTemplate = "annotation-merkle-d{depth}-{hashType}")
public class AnnotatedMerkleMembership {
    private final ZkMerkle.HashType hashType;

    public AnnotatedMerkleMembership(
            @CircuitParam("depth") int depth,
            @CircuitParam("hashType") ZkMerkle.HashType hashType) {
        this.hashType = hashType;
    }

    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkField leaf,
            @Public ZkField root,
            @Secret @FixedSize(param = "depth") ZkArray<ZkField> siblings,
            @Secret @FixedSize(param = "depth") ZkArray<ZkBool> pathBits) {
        return ZkMerkle.isMember(zk, leaf, root, siblings, pathBits, hashType);
    }
}
