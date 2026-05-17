package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC;

@ZKCircuit(name = "annotation-hash-commitment")
public class AnnotatedHashCommitment {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkField value,
            @Secret ZkField salt,
            @Public ZkField commitment) {
        return ZkMiMC.hash(zk, value, salt).isEqual(commitment);
    }
}
