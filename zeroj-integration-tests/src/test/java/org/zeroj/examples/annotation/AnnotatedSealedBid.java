package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkPoseidon;

@ZKCircuit(name = "annotation-sealed-bid", version = 1)
public class AnnotatedSealedBid {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public ZkField bidCommitment,
            @Public @UInt(bits = 64) ZkUInt reservePrice,
            @Secret @UInt(bits = 64) ZkUInt bidAmount,
            @Secret ZkField salt) {
        var commitmentMatches = ZkPoseidon.hash(
                        zk,
                        PoseidonParamsBLS12_381T3.INSTANCE,
                        bidAmount.asField(),
                        salt)
                .isEqual(bidCommitment);

        return commitmentMatches.and(bidAmount.gte(reservePrice));
    }
}
