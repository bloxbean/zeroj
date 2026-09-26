package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(name = "annotation-age-verification")
public class AnnotatedAgeVerification {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 8) ZkUInt age,
            @Public @UInt(bits = 8) ZkUInt threshold) {
        return age.gte(threshold);
    }
}
