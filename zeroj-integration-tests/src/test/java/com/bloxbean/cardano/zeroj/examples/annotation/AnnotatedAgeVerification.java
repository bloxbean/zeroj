package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(name = "annotation-age-verification")
public class AnnotatedAgeVerification {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 8) ZkUInt age,
            @Public @UInt(bits = 8) ZkUInt threshold) {
        return age.gte(threshold);
    }
}
