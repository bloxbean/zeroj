package org.zeroj.bindings.circuit;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.math.BigInteger;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.*;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.circuit.lib.zk.ZkMerkle;

/** Test-only Java authoring and host hashing, independent of recipe dispatch. */
final class MerkleFixtures {
    static CircuitBuilder circuit(int depth) {
        var builder=CircuitBuilder.create("merkle_d"+depth).publicVar("root").secretVar("leaf");
        for(int i=0;i<depth;i++)builder.secretVar("siblings_"+i);
        for(int i=0;i<depth;i++)builder.secretVar("pathBits_"+i);
        return builder.defineSignals(c->{
            var root=ZkField.publicInput(c,"root");var leaf=ZkField.secret(c,"leaf");
            var siblings=ZkArray.secretFields(c,"siblings",depth);var bits=ZkArray.secretBools(c,"pathBits",depth);
            ZkMerkle.computeRootPoseidon(new ZkContext(c),PoseidonParamsBLS12_381T3.INSTANCE,leaf,siblings,bits).assertEqual(root);
        });
    }
    static ObjectNode input(int depth,int pattern) {
        var n=GraphCodec.JSON.createObjectNode();BigInteger current=BigInteger.valueOf(42);
        n.put("leaf",current.toString());
        for(int i=0;i<depth;i++) {
            BigInteger sibling=BigInteger.valueOf(100+i);boolean right=pattern==1||(pattern==2&&i%2==1);
            n.put("siblings_"+i,sibling.toString()).put("pathBits_"+i,right?"1":"0");
            current=right?PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE,sibling,current)
                    :PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE,current,sibling);
        }
        n.put("root",current.toString());return n;
    }
}
