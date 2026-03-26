package com.bloxbean.cardano.zeroj.api;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class ZkProofEnvelopeTest {

    @Test
    void buildMinimalEnvelope() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("multiplier"))
                .proofBytes(new byte[]{1, 2, 3})
                .publicInputs(new PublicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3))))
                .vkRef(new VerificationKeyRef.ById("vk-multiplier-v1"))
                .build();

        assertEquals(ProofSystemId.GROTH16, envelope.proofSystem());
        assertEquals(CurveId.BN254, envelope.curve());
        assertEquals("multiplier", envelope.circuitId().value());
        assertArrayEquals(new byte[]{1, 2, 3}, envelope.proofBytes());
        assertEquals(2, envelope.publicInputs().size());
        assertEquals(BigInteger.valueOf(33), envelope.publicInputs().get(0));
        assertEquals(1, envelope.version());
        assertTrue(envelope.proofFormat().isEmpty());
        assertTrue(envelope.proofUri().isEmpty());
        assertTrue(envelope.createdAt().isEmpty());
    }

    @Test
    void buildFullEnvelope() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("transfer-v2"))
                .proofBytes(new byte[]{10, 20, 30})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ByHash(new byte[32]))
                .version(1)
                .domainTag("test-domain")
                .metadata(Map.of("generator", "snarkjs"))
                .proofFormat("snarkjs-json")
                .proofUri("ipfs://Qm...")
                .createdAt(1711324800L)
                .producerId("node-1")
                .build();

        assertEquals("test-domain", envelope.domainTag());
        assertEquals("snarkjs", envelope.metadata().get("generator"));
        assertEquals("snarkjs-json", envelope.proofFormat().orElse(null));
        assertEquals("ipfs://Qm...", envelope.proofUri().orElse(null));
        assertEquals(1711324800L, envelope.createdAt().orElse(null));
        assertEquals("node-1", envelope.producerId().orElse(null));
    }

    @Test
    void missingRequiredFieldsThrow() {
        assertThrows(NullPointerException.class, () ->
                ZkProofEnvelope.builder().build());

        assertThrows(NullPointerException.class, () ->
                ZkProofEnvelope.builder()
                        .proofSystem(ProofSystemId.GROTH16)
                        .build());
    }

    @Test
    void emptyProofBytesThrows() {
        assertThrows(IllegalArgumentException.class, () ->
                ZkProofEnvelope.builder()
                        .proofSystem(ProofSystemId.GROTH16)
                        .curve(CurveId.BN254)
                        .circuitId(new CircuitId("test"))
                        .proofBytes(new byte[0])
                        .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                        .vkRef(new VerificationKeyRef.ById("vk1"))
                        .build());
    }

    @Test
    void proofBytesAreDefensivelyCopied() {
        byte[] original = {1, 2, 3};
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(original)
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        original[0] = 99;
        assertEquals(1, envelope.proofBytes()[0], "Envelope should not be affected by mutation of input array");

        byte[] retrieved = envelope.proofBytes();
        retrieved[0] = 99;
        assertEquals(1, envelope.proofBytes()[0], "Envelope should not be affected by mutation of retrieved array");
    }

    @Test
    void envelopeEquality() {
        var a = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1, 2})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        var b = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1, 2})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void metadataIsImmutable() {
        var mutable = new java.util.HashMap<String, String>();
        mutable.put("key", "value");

        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .metadata(mutable)
                .build();

        mutable.put("another", "value");
        assertFalse(envelope.metadata().containsKey("another"));
        assertThrows(UnsupportedOperationException.class, () ->
                envelope.metadata().put("x", "y"));
    }
}
