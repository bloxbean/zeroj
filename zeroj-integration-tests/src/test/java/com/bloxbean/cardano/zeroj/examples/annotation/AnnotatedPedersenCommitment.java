package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPedersen;

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
