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
import com.bloxbean.cardano.zeroj.circuit.lib.zk.ZkMiMC;

@ZKCircuit(name = "annotation-sealed-bid", version = 1)
public class AnnotatedSealedBid {
    @Prove
    ZkBool prove(
            ZkContext zk,
            @Public @UInt(bits = 64) ZkUInt reservePrice,
            @Public ZkField bidCommitment,
            @Public ZkBool isAboveReserve,
            @Secret @UInt(bits = 64) ZkUInt bidAmount,
            @Secret ZkField salt) {
        var commitmentMatches = ZkMiMC.hash(zk, bidAmount.asField(), salt)
                .isEqual(bidCommitment);
        var reserveFlagMatches = bidAmount.gte(reservePrice)
                .isEqual(isAboveReserve);

        return commitmentMatches.and(reserveFlagMatches);
    }
}
