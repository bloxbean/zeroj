package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
@ZKCircuit(name="age_check")
public final class AgeCheck {
    @Prove ZkBool prove(@Public @UInt(bits=8) ZkUInt threshold, @Secret @UInt(bits=8) ZkUInt age) {
        return age.gte(threshold);
    }
}
