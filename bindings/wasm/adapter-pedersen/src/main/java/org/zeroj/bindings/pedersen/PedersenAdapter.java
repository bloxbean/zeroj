package org.zeroj.bindings.pedersen;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import org.zeroj.bindings.common.Adapter;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.common.BindingException;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenScalarCommitment;
import org.zeroj.circuit.lib.jubjub.PedersenBytesCommitment;

/** Profile-specific APIs. verify methods are only for already-disclosed openings (class V1). */
public final class PedersenAdapter implements Adapter {
    private static final G1Pedersen PUBLIC_G1 = G1Pedersen.withProvider(new PublicBlsProvider());
    @Override public JsonNode invoke(String operation, JsonNode args, BindingSession session) {
        String profile = Boundary.text(args,"curve");
        boolean g1 = switch(profile) {
            case "bls12381" -> true;
            case "jubjub" -> false;
            default -> throw Boundary.invalid();
        };
        BigInteger modulus = g1 ? MontFr381.modulus() : JubjubCurve.SUBGROUP_ORDER;
        if (operation.equals("randomBlinding")) {
            Boundary.fields(args,"curve");
            BigInteger r = g1 ? G1Pedersen.randomBlinding(session.random())
                    : PedersenCommitment.randomBlinding(session.random());
            return Boundary.object().put("blinding",r.toString());
        }
        return switch(operation) {
            case "commitScalar" -> {
                Boundary.fields(args,"curve","value","blinding");
                BigInteger v=Boundary.scalar(args,"value",modulus), r=Boundary.scalar(args,"blinding",modulus);
                session.requireSecrets();
                byte[] c=g1 ? G1Pedersen.pureJava().commitScalar(v,r).toPointBytes()
                        : PedersenCommitment.commitScalar(v,r).toPointBytes();
                yield Boundary.object().put("commitment",Boundary.hex(c));
            }
            case "verifyScalar" -> {
                Boundary.fields(args,"curve","value","blinding","commitment");
                BigInteger v=Boundary.scalar(args,"value",modulus), r=Boundary.scalar(args,"blinding",modulus);
                byte[] c=Boundary.bytes(args,"commitment",g1?48:32,g1?48:32);
                yield Boundary.object().put("valid",g1
                        ? PUBLIC_G1.verifyScalar(G1PedersenCommitment.decode(c),v,r)
                        : PedersenCommitment.verifyScalar(PedersenScalarCommitment.decode(c),v,r));
            }
            case "commitBytes" -> {
                Boundary.fields(args,"curve","data","blinding");
                byte[] data=Boundary.bytes(args,"data",0,Boundary.MAX_BYTES);
                BigInteger r=Boundary.scalar(args,"blinding",modulus);
                session.requireSecrets();
                byte[] c=g1 ? G1Pedersen.pureJava().commitBytes(data,r).toPointBytes()
                        : PedersenCommitment.commitBytes(data,r).toPointBytes();
                yield Boundary.object().put("commitment",Boundary.hex(c));
            }
            case "verifyBytes" -> {
                Boundary.fields(args,"curve","data","blinding","commitment");
                byte[] data=Boundary.bytes(args,"data",0,Boundary.MAX_BYTES);
                BigInteger r=Boundary.scalar(args,"blinding",modulus);
                byte[] c=Boundary.bytes(args,"commitment",g1?48:32,g1?48:32);
                yield Boundary.object().put("valid",g1
                        ? PUBLIC_G1.verifyBytes(G1PedersenBytesCommitment.decode(c),data,r)
                        : PedersenCommitment.verifyBytes(PedersenBytesCommitment.decode(c),data,r));
            }
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
    }
}
