package org.zeroj.verifier.groth16.bls12381;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.ZkProofEnvelope;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.codec.SnarkjsJsonCodec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Full raw envelopes: malformed data must reach each verifier, not just the transport codec. */
class Groth16AdversarialEnvelopeParityTest {
    private final Groth16BLS12381PureJavaVerifier pure = new Groth16BLS12381PureJavaVerifier();
    private final Groth16BLS12381Verifier nativeVerifier = new Groth16BLS12381Verifier();
    private static final CircuitId CIRCUIT = new CircuitId("multiplier-bls");

    @Test void malformedPointsAreRejectedAtEveryProofAndVkPosition() throws Exception {
        String proof = load("proof.json"), vk = load("verification_key.json");
        check(proof, vk, true, "valid control");
        String[] badG1 = {"[0,2,1]", "[0,1,0]", "[0,0,1]", "[-1,2,1]",
                "[" + Fp.P + ",2,1]", "[0,2]", "[0,2,1,1]"};
        for (String bad : badG1) {
            for (String slot : List.of("pi_a", "pi_c")) check(replaceArray(proof, slot, bad), vk, false, slot + bad);
            check(proof, replaceArray(vk, "vk_alpha_1", bad), false, "alpha" + bad);
            var ic = SnarkjsJsonCodec.parseVerificationKey(vk).ic();
            for (int index = 0; index < ic.size(); index++) {
                var entries = new ArrayList<String>();
                for (int i = 0; i < ic.size(); i++) entries.add(i == index ? bad : ic.get(i).toString());
                check(proof, replaceArray(vk, "IC", "[" + String.join(",", entries) + "]"), false, "IC[" + index + "]" + bad);
            }
        }
        Fp2 x = Fp2.of(Fp.ZERO, Fp.ONE);
        Fp2 y = x.square().mul(x).add(Fp2.of(Fp.of(4), Fp.of(4))).sqrt().orElseThrow();
        var torsion = new G2Point(x, y);
        assertTrue(torsion.isOnCurve());
        assertFalse(torsion.isInSubgroup());
        String[] badG2 = {"[[0,1],[" + y.c0().value() + "," + y.c1().value() + "],[1,0]]",
                "[[0,0],[1,0],[0,0]]", "[[0,0],[0,0],[1,0]]",
                "[[-1,0],[1,0],[1,0]]", "[[" + Fp.P + ",0],[1,0],[1,0]]",
                "[[0],[1,0],[1,0]]", "[[0,0,0],[1,0],[1,0]]", "[[0,0],[1,0]]"};
        for (String bad : badG2) {
            check(replaceArray(proof, "pi_b", bad), vk, false, "B" + bad);
            for (String slot : List.of("vk_beta_2", "vk_gamma_2", "vk_delta_2"))
                check(proof, replaceArray(vk, slot, bad), false, slot + bad);
        }
    }

    private void check(String proof, String vk, boolean expected, String label) throws Exception {
        byte[] vkBytes = vk.getBytes(StandardCharsets.UTF_8);
        var envelope = ZkProofEnvelope.builder().proofSystem(ProofSystemId.GROTH16).curve(CurveId.BLS12_381)
                .circuitId(CIRCUIT).proofFormat("snarkjs-json").proofBytes(proof.getBytes(StandardCharsets.UTF_8))
                .publicInputs(SnarkjsJsonCodec.parsePublicInputs(load("public.json")))
                .vkRef(new VerificationKeyRef.ByHash(MessageDigest.getInstance("SHA-256").digest(vkBytes))).build();
        var material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BLS12_381, CIRCUIT);
        var pj = assertDoesNotThrow(() -> pure.verify(envelope, material), label);
        var bl = assertDoesNotThrow(() -> nativeVerifier.verify(envelope, material), label);
        assertEquals(expected, pj.proofValid(), "Java " + label);
        assertEquals(expected, bl.proofValid(), "blst " + label);
        assertEquals(pj.reasonCode(), bl.reasonCode(), label);
    }

    private static String replaceArray(String json, String key, String replacement) {
        int name = json.indexOf('"' + key + '"');
        assertTrue(name >= 0, key);
        int start = json.indexOf('[', json.indexOf(':', name));
        int depth = 0;
        for (int i = start; i < json.length(); i++) {
            if (json.charAt(i) == '[') depth++;
            if (json.charAt(i) == ']' && --depth == 0) return json.substring(0, start) + replacement + json.substring(i + 1);
        }
        throw new AssertionError("Unterminated " + key);
    }

    private static String load(String file) throws Exception {
        try (var in = Groth16AdversarialEnvelopeParityTest.class.getResourceAsStream(
                "/test-vectors/groth16-bls12381/" + file)) {
            assertNotNull(in);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
