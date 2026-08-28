package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

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
