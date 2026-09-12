package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.CircuitParam;
import org.zeroj.circuit.annotation.FixedSize;
import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkArray;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.zk.ZkMerkle;

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
