package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CborEnvelopeCodecTest {

    @Test
    void roundTripWithByHashRef() {
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("multiplier"))
                .proofBytes(new byte[]{1, 2, 3, 4, 5})
                .publicInputs(new PublicInputs(List.of(
                        BigInteger.valueOf(33),
                        BigInteger.valueOf(3))))
                .vkRef(new VerificationKeyRef.ByHash(new byte[32]))
                .build();

        byte[] cbor = CborEnvelopeCodec.encode(original);
        assertNotNull(cbor);
        assertTrue(cbor.length > 0);

        var decoded = CborEnvelopeCodec.decode(cbor);
        assertEquals(original.proofSystem(), decoded.proofSystem());
        assertEquals(original.curve(), decoded.curve());
        assertEquals(original.circuitId(), decoded.circuitId());
        assertArrayEquals(original.proofBytes(), decoded.proofBytes());
        assertEquals(original.publicInputs(), decoded.publicInputs());
        assertEquals(original.version(), decoded.version());
    }

    @Test
    void roundTripWithByIdRef() {
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("transfer-v2"))
                .proofBytes(new byte[]{10, 20, 30})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk-transfer-v2"))
                .build();

        byte[] cbor = CborEnvelopeCodec.encode(original);
        var decoded = CborEnvelopeCodec.decode(cbor);

        assertInstanceOf(VerificationKeyRef.ById.class, decoded.vkRef());
        assertEquals("vk-transfer-v2", ((VerificationKeyRef.ById) decoded.vkRef()).id());
    }

    @Test
    void roundTripLargePublicInputs() {
        // BN254 field-size numbers
        var fieldOrder = new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
        var original = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(
                        fieldOrder.subtract(BigInteger.ONE),
                        BigInteger.ZERO,
                        BigInteger.valueOf(42))))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        var decoded = CborEnvelopeCodec.decode(CborEnvelopeCodec.encode(original));
        assertEquals(3, decoded.publicInputs().size());
        assertEquals(fieldOrder.subtract(BigInteger.ONE), decoded.publicInputs().get(0));
        assertEquals(BigInteger.ZERO, decoded.publicInputs().get(1));
        assertEquals(BigInteger.valueOf(42), decoded.publicInputs().get(2));
    }

    @Test
    void roundTripFromRealSnarkjsVectors() {
        var proof = SnarkjsJsonCodec.parseProof(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/proof.json"));
        var vk = SnarkjsJsonCodec.parseVerificationKey(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/verification_key.json"));
        var inputs = SnarkjsJsonCodec.parsePublicInputs(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/public.json"));

        var envelope = SnarkjsJsonCodec.toEnvelope(proof, vk, inputs, new CircuitId("multiplier"));

        byte[] cbor = CborEnvelopeCodec.encode(envelope);
        var decoded = CborEnvelopeCodec.decode(cbor);

        assertEquals(envelope.proofSystem(), decoded.proofSystem());
        assertEquals(envelope.curve(), decoded.curve());
        assertEquals(envelope.circuitId(), decoded.circuitId());
        assertArrayEquals(envelope.proofBytes(), decoded.proofBytes());
        assertEquals(envelope.publicInputs(), decoded.publicInputs());
    }

    @Test
    void decodeMalformedCborThrows() {
        assertThrows(CodecException.class, () ->
                CborEnvelopeCodec.decode(new byte[]{0x00, 0x01, 0x02}));
    }
}
