package org.zeroj.bindings.groth16;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.zeroj.api.*;
import org.zeroj.bindings.common.*;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.bls12381.field.MontFp381;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

/** Mathematical verification only. Applications must select a trusted VK and expected public inputs. */
public final class Groth16VerifierAdapter implements Adapter {
    public static final BigInteger FR = MontFr381.modulus();
    @Override public JsonNode invoke(String operation, JsonNode args, BindingSession session) {
        if (!operation.equals("verify")) throw new BindingException("UNSUPPORTED_OPERATION");
        Boundary.fields(args,"proof","verificationKey","publicInputs");
        var values = scalars(args.get("publicInputs"));
        return Boundary.object().put("valid",verify(args.get("proof"),args.get("verificationKey"),values));
    }
    public static List<BigInteger> scalars(JsonNode node) {
        if (node == null || !node.isArray() || node.size() > 64) throw Boundary.invalid();
        var values = new ArrayList<BigInteger>();
        for (var v : node) {
            if (!v.isTextual()) throw Boundary.invalid();
            values.add(Boundary.decimal(v.textValue(),FR));
        }
        return values;
    }
    public static void keyShape(JsonNode vk) {
        Boundary.fields(vk,"protocol","curve","nPublic","vk_alpha_1","vk_beta_2","vk_gamma_2",
                "vk_delta_2","vk_alphabeta_12","IC");
        profile(vk);
        Boundary.integer(vk,"nPublic",0,64);
        for (String name : List.of("vk_alpha_1","vk_beta_2","vk_gamma_2","vk_delta_2","vk_alphabeta_12","IC"))
            canonicalCoordinates(vk.get(name),0);
    }
    public static boolean verify(JsonNode proof, JsonNode vk, List<BigInteger> values) {
        Boundary.fields(proof,"protocol","curve","pi_a","pi_b","pi_c");
        profile(proof); keyShape(vk);
        for (String name : List.of("pi_a","pi_b","pi_c")) canonicalCoordinates(proof.get(name),0);
        var id = new CircuitId("zeroj-wasm-application-selected");
        var envelope = ZkProofEnvelope.builder().proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(id).vkRef(new VerificationKeyRef.ById("application-selected"))
                .proofBytes(proof.toString().getBytes(StandardCharsets.UTF_8))
                .publicInputs(new PublicInputs(values)).build();
        var material = VerificationMaterial.of(vk.toString().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16,CurveId.BLS12_381,id);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope,material).proofValid();
    }
    private static void profile(JsonNode n) {
        if (!Boundary.text(n,"protocol").equals("groth16") || !Boundary.text(n,"curve").equals("bls12381"))
            throw new BindingException("UNSUPPORTED_PROFILE");
    }
    private static void canonicalCoordinates(JsonNode n, int depth) {
        if (n == null || depth > 4) throw Boundary.invalid();
        if (n.isArray()) {
            if (n.size() < 1 || n.size() > 65) throw Boundary.invalid();
            for (var v : n) canonicalCoordinates(v,depth+1);
        } else if (n.isTextual()) Boundary.decimal(n.textValue(),MontFp381.modulus());
        else throw Boundary.invalid();
    }
}
