package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkPoseidon;
@ZKCircuit(name="poseidon_opening")
public final class PoseidonOpening {
    @Prove void prove(ZkContext zk,@Public ZkField commitment,@Secret ZkField value,@Secret ZkField salt) {
        ZkPoseidon.hash(zk,PoseidonParamsBLS12_381T3.INSTANCE,value,salt).assertEqual(commitment);
    }
}
