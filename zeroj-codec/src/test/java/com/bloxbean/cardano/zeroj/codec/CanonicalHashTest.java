package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CanonicalHashTest {

    @Test
    void hashIsDeterministic() {
        var envelope = makeEnvelope();
        byte[] hash1 = CanonicalHash.hash(envelope);
        byte[] hash2 = CanonicalHash.hash(envelope);

        assertEquals(32, hash1.length);
        assertArrayEquals(hash1, hash2, "Same envelope must produce identical hashes");
    }

    @Test
    void differentProofsProduceDifferentHashes() {
        var a = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1, 2, 3})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        var b = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{4, 5, 6})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        assertFalse(Arrays.equals(CanonicalHash.hash(a), CanonicalHash.hash(b)));
    }

    @Test
    void differentCurvesProduceDifferentHashes() {
        var bn254 = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        var bls = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BLS12_381)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        assertFalse(Arrays.equals(CanonicalHash.hash(bn254), CanonicalHash.hash(bls)));
    }

    @Test
    void metadataDoesNotAffectHash() {
        var withMeta = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .metadata(java.util.Map.of("extra", "data"))
                .producerId("node-1")
                .createdAt(123456789L)
                .build();

        var withoutMeta = ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("test"))
                .proofBytes(new byte[]{1})
                .publicInputs(new PublicInputs(List.of(BigInteger.ONE)))
                .vkRef(new VerificationKeyRef.ById("vk1"))
                .build();

        assertArrayEquals(CanonicalHash.hash(withMeta), CanonicalHash.hash(withoutMeta),
                "Optional metadata should not affect canonical hash");
    }

    @Test
    void hashFromRealSnarkjsVectors() {
        var proof = SnarkjsJsonCodec.parseProof(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/proof.json"));
        var vk = SnarkjsJsonCodec.parseVerificationKey(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/verification_key.json"));
        var inputs = SnarkjsJsonCodec.parsePublicInputs(
                getClass().getResourceAsStream("/test-vectors/groth16-bn254/public.json"));

        var envelope = SnarkjsJsonCodec.toEnvelope(proof, vk, inputs, new CircuitId("multiplier"));

        byte[] hash = CanonicalHash.hash(envelope);
        assertEquals(32, hash.length);

        // Hash must be reproducible
        byte[] hash2 = CanonicalHash.hash(envelope);
        assertArrayEquals(hash, hash2);
    }

    private ZkProofEnvelope makeEnvelope() {
        return ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId(new CircuitId("multiplier"))
                .proofBytes(new byte[]{1, 2, 3, 4})
                .publicInputs(new PublicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3))))
                .vkRef(new VerificationKeyRef.ById("vk-multiplier"))
                .build();
    }
}
