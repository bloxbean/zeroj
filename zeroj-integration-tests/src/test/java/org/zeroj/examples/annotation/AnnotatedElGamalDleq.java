package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.zk.ZkElGamal;

/**
 * ADR-0052 annotation example: the discrete-log-equality relation of {@code elgamal-jubjub-v1}
 * §9.2, {@code P = [x]·G} and {@code D = [x]·X}. The public inputs are exactly a
 * {@code DleqStatement}'s, {@code X.u, X.v, P.u, P.v, D.u, D.v}, so one circuit serves both
 * proofs of possession ({@code X = G}, {@code D = P}) and decryption-share proofs
 * ({@code X = A}).
 */
@ZKCircuit(name = "annotation-elgamal-dleq")
public class AnnotatedElGamalDleq {
    @Prove
    void prove(
            ZkContext zk,
            @Public ZkField baseU,
            @Public ZkField baseV,
            @Public ZkField keyU,
            @Public ZkField keyV,
            @Public ZkField shareU,
            @Public ZkField shareV,
            @Secret @UInt(bits = 252) ZkUInt secret) {
        ZkElGamal.assertDiscreteLogEquality(zk, secret, baseU, baseV, keyU, keyV, shareU, shareV);
    }
}
