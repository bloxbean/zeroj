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
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;

/**
 * ADR-0052 annotation example: a one-bit ballot encrypted under an {@code elgamal-jubjub-v1}
 * election key. The public inputs are exactly the spec §8 encryption statement,
 * {@code PK.u, PK.v, A.u, A.v, B.u, B.v}, so a verifier can check a proof against
 * {@code EncryptionStatement.publicInputs()} verbatim during admission.
 */
@ZKCircuit(name = "annotation-elgamal-ballot")
public class AnnotatedElGamalBallot {
    @Prove
    void prove(
            ZkContext zk,
            @Public ZkField keyU,
            @Public ZkField keyV,
            @Public ZkField handleU,
            @Public ZkField handleV,
            @Public ZkField blindedU,
            @Public ZkField blindedV,
            @Secret @UInt(bits = 1) ZkUInt vote,
            @Secret @UInt(bits = 252) ZkUInt randomness) {
        var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk, keyU, keyV);
        ZkElGamal.encrypt(zk, vote, randomness, key)
                .assertAffineEquals(zk, handleU, handleV, blindedU, blindedV);
    }
}
