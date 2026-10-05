package org.zeroj.examples.annotation;

import org.zeroj.circuit.annotation.Prove;
import org.zeroj.circuit.annotation.Public;
import org.zeroj.circuit.annotation.Secret;
import org.zeroj.circuit.annotation.UInt;
import org.zeroj.circuit.annotation.ZKCircuit;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema;
import org.zeroj.circuit.lib.jubjub.PedersenVectorSchema.Entry;
import org.zeroj.circuit.lib.zk.ZkPedersenVector;

import java.util.List;

/**
 * ADR-0051 annotation example: a {@code pedersen-jubjub-vector-v1} commitment to two values under
 * a fixed schema. The schema's digest is a public input constrained to the schema, so the
 * verification key and the public statement both name the schema; the verifier checks the digest
 * against the one it expects (spec §5). Each value is declared at its schema width.
 */
@ZKCircuit(name = "annotation-vector-commitment")
public class AnnotatedVectorCommitment {

    static final PedersenVectorSchema SCHEMA = PedersenVectorSchema.of("zeroj.example.balance", 1,
            List.of(new Entry("amount", 64), new Entry("asset", 32)));

    @Prove
    void prove(
            ZkContext zk,
            @Secret @UInt(bits = 64) ZkUInt amount,
            @Secret @UInt(bits = 32) ZkUInt asset,
            @Secret @UInt(bits = 252) ZkUInt blinding,
            @Public ZkField schemaDigest,
            @Public ZkField u,
            @Public ZkField v) {
        var binding = ZkPedersenVector.bindSchema(zk, SCHEMA, schemaDigest);
        ZkPedersenVector.commit(zk, binding, List.of(amount, asset), blinding)
                .assertAffineEquals(zk, u, v);
    }
}
