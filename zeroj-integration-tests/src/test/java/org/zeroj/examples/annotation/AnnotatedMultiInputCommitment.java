package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkPoseidonN;

@ZKCircuit(name = "annotation-multi-input-commitment", version = 1)
public class AnnotatedMultiInputCommitment {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Secret ZkField owner,
            @Secret ZkField assetId,
            @Secret ZkField nonce,
            @Public ZkField commitment) {
        return ZkPoseidonN.hash(
                        zk,
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        owner,
                        assetId,
                        nonce)
                .isEqual(commitment);
    }
}
