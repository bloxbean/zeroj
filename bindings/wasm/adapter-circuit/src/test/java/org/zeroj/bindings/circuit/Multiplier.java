package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
@ZKCircuit(name="multiplier")
public final class Multiplier {
    @Prove void prove(@Public ZkField product, @Secret ZkField x, @Secret ZkField y) {
        x.mul(y).assertEqual(product);
    }
}
