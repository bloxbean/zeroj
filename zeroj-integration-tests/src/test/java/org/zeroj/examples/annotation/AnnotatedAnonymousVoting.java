package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

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
