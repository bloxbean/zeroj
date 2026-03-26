package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeValidatorTest {

    @Test
    void validEnvelopePassesValidation() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1, 2, 3})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        var errors = EnvelopeValidator.validate(envelope);
        assertTrue(errors.isEmpty(), "Valid envelope should have no errors: " + errors);
    }

    @Test
    void versionZeroIsInvalid() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .version(0)
                .build();

        var errors = EnvelopeValidator.validate(envelope);
        assertFalse(errors.isEmpty());
        assertTrue(errors.stream().anyMatch(e -> e.contains("version")));
    }

    @Test
    void futureVersionIsInvalid() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .version(999)
                .build();

        var errors = EnvelopeValidator.validate(envelope);
        assertFalse(errors.isEmpty());
        assertTrue(errors.stream().anyMatch(e -> e.contains("unsupported")));
    }

    @Test
    void requireValidThrowsOnInvalidEnvelope() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .version(0)
                .build();

        assertThrows(CodecException.class, () -> EnvelopeValidator.requireValid(envelope));
    }

    @Test
    void requireValidPassesForValidEnvelope() {
        var envelope = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        assertDoesNotThrow(() -> EnvelopeValidator.requireValid(envelope));
    }
}
