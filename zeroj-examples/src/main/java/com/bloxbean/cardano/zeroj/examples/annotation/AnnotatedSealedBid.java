package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkContext;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkField;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkPoseidon;

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
