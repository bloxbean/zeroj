package org.zeroj.bindings.circuit;
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.zk.ZkSha256;
@ZKCircuit(name="sha256_abc")
public final class Sha256Preimage {
    @Prove void prove(ZkContext zk, @Public @FixedSize(32) ZkBytes digest,
                     @Secret @FixedSize(3) ZkBytes message) {
        ZkSha256.hash(zk,message).assertEqual(digest);
    }
}
