package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.circuit.annotation.Prove;
import com.bloxbean.cardano.zeroj.circuit.annotation.Public;
import com.bloxbean.cardano.zeroj.circuit.annotation.Secret;
import com.bloxbean.cardano.zeroj.circuit.annotation.UInt;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZKCircuit;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkBool;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkUInt;

@ZKCircuit(name = "annotation-private-transfer")
public class AnnotatedPrivateTransfer {
    @Prove
    ZkBool prove(
            @Secret @UInt(bits = 16) ZkUInt balanceBefore,
            @Secret @UInt(bits = 16) ZkUInt transferAmount,
            @Public @UInt(bits = 16) ZkUInt publicAmount,
            @Public @UInt(bits = 16) ZkUInt balanceAfter) {
        return transferAmount.isEqual(publicAmount)
                .and(balanceBefore.sub(transferAmount).isEqual(balanceAfter));
    }
}
