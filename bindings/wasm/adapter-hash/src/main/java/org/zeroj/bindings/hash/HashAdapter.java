package org.zeroj.bindings.hash;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.zeroj.bindings.common.Adapter;
import org.zeroj.bindings.common.BindingSession;
import org.zeroj.bindings.common.Boundary;
import org.zeroj.bindings.common.BindingException;
import org.zeroj.circuit.lib.jubjub.Blake2bDigest;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

public final class HashAdapter implements Adapter {
    @Override public JsonNode invoke(String operation, JsonNode args, BindingSession session) {
        if (operation.equals("poseidonBls12381T3")) {
            Boundary.fields(args,"left","right");
            var params=PoseidonParamsBLS12_381T3.INSTANCE;
            // BigInteger implementation is not a secret-safe browser path.
            session.requireSecrets();
            return Boundary.object().put("value",PoseidonHash.hash(params,
                    Boundary.scalar(args,"left",params.field().prime()),
                    Boundary.scalar(args,"right",params.field().prime())).toString());
        }
        if (operation.equals("blake2b")) {
            Boundary.fields(args,"data","outputBytes");
            byte[] input = Boundary.bytes(args,"data",0,Boundary.MAX_BYTES);
            return Boundary.object().put("digest",Boundary.hex(Blake2bDigest.digest(input,
                    Boundary.integer(args,"outputBytes",1,64))));
        }
        Boundary.fields(args,"data");
        byte[] input = Boundary.bytes(args,"data",0,Boundary.MAX_BYTES);
        String algorithm = switch (operation) {
            case "sha256" -> "SHA-256";
            case "sha512" -> "SHA-512";
            default -> throw new BindingException("UNSUPPORTED_OPERATION");
        };
        try { return Boundary.object().put("digest",Boundary.hex(MessageDigest.getInstance(algorithm).digest(input))); }
        catch (NoSuchAlgorithmException e) { throw new BindingException("UNSUPPORTED_ALGORITHM"); }
    }
}
