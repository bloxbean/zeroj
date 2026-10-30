package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkMerkle;
@ZKCircuit(name="allowlist_d1")
public final class Allowlist {
    @Prove void prove(ZkContext zk,@Public ZkField root,
            @Secret ZkField leaf,@Secret(name="siblings") @FixedSize(1) ZkArray<ZkField> siblings,
            @Secret(name="pathBits") @FixedSize(1) ZkArray<ZkBool> pathBits) {
        ZkMerkle.computeRootPoseidon(zk,PoseidonParamsBLS12_381T3.INSTANCE,leaf,siblings,pathBits).assertEqual(root);
    }
}
