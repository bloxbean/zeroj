package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidonN;

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
