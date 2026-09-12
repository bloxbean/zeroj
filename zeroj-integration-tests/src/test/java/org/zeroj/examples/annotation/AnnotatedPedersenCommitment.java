package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkPedersen;

@ZKCircuit(name = "annotation-pedersen-commitment")
public class AnnotatedPedersenCommitment {
    @Prove
    void prove(
            ZkContext zk,
            @Secret @UInt(bits = 16) ZkUInt value,
            @Secret @UInt(bits = 16) ZkUInt blinding,
            @Public ZkField expectedU,
            @Public ZkField expectedV) {
        ZkPedersen.commit(zk, value, blinding, 16)
                .assertAffineEquals(zk, expectedU, expectedV);
    }
}
