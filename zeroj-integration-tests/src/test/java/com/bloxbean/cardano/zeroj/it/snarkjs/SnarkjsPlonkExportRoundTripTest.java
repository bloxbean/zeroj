package com.bloxbean.cardano.zeroj.it.snarkjs;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.codec.CanonicalHash;
import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec;
import com.bloxbean.cardano.zeroj.crypto.snarkjs.SnarkjsPlonkJson;
import com.bloxbean.cardano.zeroj.verifier.plonk.PlonkBLS12381Verifier;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplier;
import static com.bloxbean.cardano.zeroj.it.snarkjs.SnarkjsInteropSupport.multiplierWitness;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0047 M3, offline half (no snarkjs needed, runs in the default build): a ZeroJ-native PlonK
 * setup + proof exported as snarkjs JSON is accepted by ZeroJ's own snarkjs-format PlonK verifier
 * through the snarkjs codec, and tampering is rejected. The live-CLI counterpart is
 * {@link SnarkjsPlonkInteropTest}.
 */
class SnarkjsPlonkExportRoundTripTest {

    @Test
    void exportedZeroJPlonkArtifacts_verifyThroughSnarkjsCodecAndZeroJVerifier() {
        var circuit = multiplier();
        var run = ZeroJPlonk.setupAndProve(circuit, multiplierWitness(circuit, 3, 11));
        String vkJson = SnarkjsPlonkJson.verificationKeyJson(run.pk());
        String proofJson = SnarkjsPlonkJson.proofJson(run.proof());
        String publicJson = SnarkjsPlonkJson.publicJson(run.publicInputs());

        var vk = SnarkjsPlonkCodec.parseVerificationKey(vkJson);
        assertEquals(run.pk().nPublic(), vk.nPublic());
        assertEquals(Integer.numberOfTrailingZeros(run.pk().domainSize()), vk.power());
        assertEquals(run.pk().omega().toBigInteger(), vk.w());
        assertEquals("bls12381", vk.curve());

        var circuitId = new CircuitId("adr-0047-plonk-roundtrip");
        var material = VerificationMaterial.of(vkJson.getBytes(StandardCharsets.UTF_8), ProofSystemId.PLONK,
                CurveId.BLS12_381, circuitId, CanonicalHash.sha256(vkJson.getBytes(StandardCharsets.UTF_8)));
        var verifier = new PlonkBLS12381Verifier();
        assertTrue(verifier.verify(SnarkjsPlonkCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson, circuitId), material)
                .proofValid(), "exported ZeroJ PlonK artifacts must verify through the snarkjs codec");

        String wrongPublic = SnarkjsPlonkJson.publicJson(new BigInteger[]{BigInteger.valueOf(34)});
        assertFalse(verifier.verify(SnarkjsPlonkCodec.toEnvelopeFromJson(proofJson, vkJson, wrongPublic, circuitId), material)
                .proofValid());
    }
}
