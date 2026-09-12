package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.zk.ZkMiMC;

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
