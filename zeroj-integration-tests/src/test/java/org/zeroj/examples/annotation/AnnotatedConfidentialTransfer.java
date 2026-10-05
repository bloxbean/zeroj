package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkPedersen;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;

import java.util.List;

/**
 * ADR-0051 annotation example: a confidential transfer over {@code pedersen-jubjub-v1}
 * commitments. The input and output amounts stay secret; the verifier sees both commitments as
 * affine {@code (u, v)} public inputs and the fee in clear. {@code assertBalanced} proves
 * {@code in = out + fee} over the integers, refusing any layout that could wrap mod {@code l}.
 */
@ZKCircuit(name = "annotation-confidential-transfer")
public class AnnotatedConfidentialTransfer {
    @Prove
    void prove(
            ZkContext zk,
            @Secret @UInt(bits = 64) ZkUInt inAmount,
            @Secret @UInt(bits = 252) ZkUInt inBlinding,
            @Secret @UInt(bits = 64) ZkUInt outAmount,
            @Secret @UInt(bits = 252) ZkUInt outBlinding,
            @Public ZkField inU,
            @Public ZkField inV,
            @Public ZkField outU,
            @Public ZkField outV,
            @Public @UInt(bits = 32) ZkUInt fee) {
        var in = ZkPedersenCommitment.commit(zk, inAmount, inBlinding);
        var out = ZkPedersenCommitment.commit(zk, outAmount, outBlinding);
        in.assertAffineEquals(zk, inU, inV);
        out.assertAffineEquals(zk, outU, outV);
        ZkPedersen.assertBalanced(zk,
                List.of(ZkPedersen.Term.of(in)),
                List.of(ZkPedersen.Term.of(out), ZkPedersen.Term.amount(fee)));
    }
}
