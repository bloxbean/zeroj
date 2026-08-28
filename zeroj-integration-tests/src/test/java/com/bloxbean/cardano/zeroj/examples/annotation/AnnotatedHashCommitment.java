package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC;

/**
 * BN254/off-chain MiMC adapter example.
 *
 * <p>Cardano-facing hash examples use explicit BLS12-381 Poseidon params
 * instead. This class remains as the small MiMC symbolic adapter example.</p>
 */
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
