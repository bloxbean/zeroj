package com.bloxbean.cardano.zeroj.api;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ModelTypesTest {

    // --- ProofSystemId ---

    @Test
    void proofSystemIdRoundTrip() {
        for (ProofSystemId id : ProofSystemId.values()) {
            assertEquals(id, ProofSystemId.fromValue(id.value()));
        }
    }

    @Test
    void proofSystemIdUnknownThrows() {
        assertThrows(IllegalArgumentException.class, () -> ProofSystemId.fromValue("unknown"));
    }

    // --- CurveId ---

    @Test
    void curveIdRoundTrip() {
        assertEquals(CurveId.BN254, CurveId.fromValue("bn128"));
        assertEquals(CurveId.BLS12_381, CurveId.fromValue("bls12381"));
    }

    @Test
    void curveIdUnknownThrows() {
        assertThrows(IllegalArgumentException.class, () -> CurveId.fromValue("secp256k1"));
    }

    // --- CircuitId ---

    @Test
    void circuitIdValid() {
        var id = new CircuitId("multiplier-v1");
        assertEquals("multiplier-v1", id.value());
        assertEquals("multiplier-v1", id.toString());
    }

    @Test
    void circuitIdNullThrows() {
        assertThrows(NullPointerException.class, () -> new CircuitId(null));
    }

    @Test
    void circuitIdBlankThrows() {
        assertThrows(IllegalArgumentException.class, () -> new CircuitId(""));
        assertThrows(IllegalArgumentException.class, () -> new CircuitId("   "));
    }

    // --- PublicInputs ---

    @Test
    void publicInputsImmutable() {
        var mutable = new java.util.ArrayList<>(List.of(BigInteger.ONE, BigInteger.TWO));
        var inputs = new PublicInputs(mutable);
        mutable.add(BigInteger.TEN);
        assertEquals(2, inputs.size());
        assertThrows(UnsupportedOperationException.class, () -> inputs.values().add(BigInteger.ZERO));
    }

    @Test
    void publicInputsNullThrows() {
        assertThrows(NullPointerException.class, () -> new PublicInputs(null));
    }

    // --- Witness ---

    @Test
    void witnessDefensivelyCopied() {
        byte[] data = {1, 2, 3};
        var w = new Witness(data);
        data[0] = 99;
        assertEquals(1, w.data()[0]);
    }

    @Test
    void witnessEquality() {
        assertEquals(new Witness(new byte[]{1, 2}), new Witness(new byte[]{1, 2}));
        assertNotEquals(new Witness(new byte[]{1, 2}), new Witness(new byte[]{1, 3}));
    }

    // --- VerificationKeyRef ---

    @Test
    void vkRefByHash() {
        var hash = new byte[32];
        hash[0] = 42;
        var ref = new VerificationKeyRef.ByHash(hash);
        hash[0] = 99;
        assertEquals(42, ref.hash()[0], "ByHash should defensively copy");
    }

    @Test
    void vkRefByHashWrongLengthThrows() {
        assertThrows(IllegalArgumentException.class, () -> new VerificationKeyRef.ByHash(new byte[16]));
    }

    @Test
    void vkRefById() {
        var ref = new VerificationKeyRef.ById("vk-circuit-v1");
        assertEquals("vk-circuit-v1", ref.id());
    }

    @Test
    void vkRefByIdBlankThrows() {
        assertThrows(IllegalArgumentException.class, () -> new VerificationKeyRef.ById(""));
    }

    @Test
    void vkRefSealed() {
        // Verify sealed interface works with pattern matching
        VerificationKeyRef ref = new VerificationKeyRef.ById("test");
        String result = switch (ref) {
            case VerificationKeyRef.ByHash h -> "hash";
            case VerificationKeyRef.ById id -> "id:" + id.id();
        };
        assertEquals("id:test", result);
    }

    // --- VerificationResult ---

    @Test
    void verificationResultOk() {
        var r = VerificationResult.ok();
        assertTrue(r.proofValid());
        assertTrue(r.protocolValid().orElse(false));
        assertTrue(r.accepted());
        assertTrue(r.reasonCode().isEmpty());
    }

    @Test
    void verificationResultCryptoValid() {
        var r = VerificationResult.cryptoValid();
        assertTrue(r.proofValid());
        assertTrue(r.protocolValid().isEmpty());
        assertFalse(r.accepted());
    }

    @Test
    void verificationResultProofInvalid() {
        var r = VerificationResult.proofInvalid("pairing check failed");
        assertFalse(r.proofValid());
        assertFalse(r.accepted());
        assertEquals(VerificationResult.ReasonCode.INVALID_PROOF, r.reasonCode().orElse(null));
        assertEquals("pairing check failed", r.message().orElse(null));
    }

    @Test
    void verificationResultPolicyRejected() {
        var r = VerificationResult.policyRejected(VerificationResult.ReasonCode.STALE_STATE_ROOT, "root mismatch");
        assertTrue(r.proofValid());
        assertFalse(r.protocolValid().orElse(true));
        assertFalse(r.accepted());
    }

    // --- VerificationMaterial ---

    @Test
    void verificationMaterialDefensivelyCopied() {
        byte[] vk = {1, 2, 3};
        var mat = VerificationMaterial.of(vk, ProofSystemId.GROTH16, CurveId.BN254, new CircuitId("test"));
        vk[0] = 99;
        assertEquals(1, mat.vkBytes()[0]);
    }

    @Test
    void verificationMaterialEmptyThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                VerificationMaterial.of(new byte[0], ProofSystemId.GROTH16, CurveId.BN254, new CircuitId("test")));
    }
}
