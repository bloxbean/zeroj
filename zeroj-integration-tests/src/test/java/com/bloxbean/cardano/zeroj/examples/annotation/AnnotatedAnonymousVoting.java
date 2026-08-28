package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon;

@ZKCircuit(name = "annotation-anonymous-vote", version = 1)
public class AnnotatedAnonymousVoting {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField commitment,
            @Secret ZkBool vote,
            @Secret ZkField nullifier) {
        return ZkPoseidon.hash(zk, PoseidonParamsBLS12_381T3.INSTANCE, vote.asField(), nullifier)
                .isEqual(commitment);
    }
}
