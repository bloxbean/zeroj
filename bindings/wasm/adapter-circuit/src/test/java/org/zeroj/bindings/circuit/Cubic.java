package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
@ZKCircuit(name="cubic")
public final class Cubic {
    @Prove void prove(ZkContext zk, @Public ZkField y, @Secret ZkField x) {
        x.mul(x).mul(x).add(x).add(zk.constant(5)).assertEqual(y);
    }
}
