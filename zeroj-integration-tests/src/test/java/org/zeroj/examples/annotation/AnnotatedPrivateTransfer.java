package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkBool;
import org.zeroj.circuit.annotation.ZkUInt;

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
