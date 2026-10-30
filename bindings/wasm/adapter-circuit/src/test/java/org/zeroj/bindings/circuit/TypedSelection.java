package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
@ZKCircuit(name="symbolic_select")
public final class TypedSelection {
    @Prove void prove(@Public ZkField selected,@Secret ZkBool chooseLeft,@Secret ZkField left,@Secret ZkField right) {
        chooseLeft.select(left,right).assertEqual(selected);
    }
}
