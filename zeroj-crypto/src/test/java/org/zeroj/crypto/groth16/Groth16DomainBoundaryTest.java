package org.zeroj.crypto.groth16;

import org.junit.jupiter.api.Test;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381Verifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class Groth16DomainBoundaryTest {
    @Test void circuitsAcrossPowerOfTwoBoundaryProveAndBindPublicInput() {
        var one = Map.of(0, BigInteger.ONE);
        var multiplier = new R1CSConstraint(Map.of(2, BigInteger.ONE), Map.of(3, BigInteger.ONE), Map.of(1, BigInteger.ONE));
        BigInteger[] witness = {BigInteger.ONE, BigInteger.valueOf(33), BigInteger.valueOf(3), BigInteger.valueOf(11)};
        for (int rows : new int[]{7, 8, 9}) {
            var constraints = new ArrayList<R1CSConstraint>();
            constraints.add(new R1CSConstraint(one, one, one));
            while (constraints.size() < rows) constraints.add(multiplier);
            // Explicitly opted-in development setup (test task); this public tau is not a ceremony.
            try (var keys = Groth16Keys.setupInMemory(constraints, 4, 1, BigInteger.valueOf(1234567))) {
                assertEquals(rows <= 8 ? 8 : 16, keys.domain());
                var proof = keys.prove(witness, constraints);
                String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
                String proofJson = SnarkjsGroth16Json.proofJson(proof);
                CircuitId circuit = new CircuitId("domain-boundary-" + rows);
                var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8),
                        ProofSystemId.GROTH16, CurveId.BLS12_381, circuit);
                for (var verifier : List.of(new Groth16BLS12381PureJavaVerifier(), new Groth16BLS12381Verifier())) {
                    assertTrue(verifier.verify(SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, "[33]", circuit), material).proofValid(), "rows=" + rows);
                    assertFalse(verifier.verify(SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, "[34]", circuit), material).proofValid(), "wrong input rows=" + rows);
                }
            }
        }
    }
}
