package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(name = "annotation-range-proof")
public class AnnotatedRangeProof {
    @Secret
    @UInt(bits = 16)
    ZkUInt secret;

    @Public
    @UInt(bits = 16)
    ZkUInt lo;

    @Public
    @UInt(bits = 16)
    ZkUInt hi;

    @Prove
    ZkBool inRange() {
        return secret.gte(lo).and(secret.lte(hi));
    }
}
