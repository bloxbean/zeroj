package com.bloxbean.cardano.zeroj.api;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * Everything needed to verify a proof — the verification key plus metadata.
 *
 * @param vkBytes       raw verification key bytes (canonical encoding)
 * @param proofSystemId the proof system this VK is for
 * @param curveId       the elliptic curve this VK is for
 * @param circuitId     the circuit this VK corresponds to
 * @param vkHash        SHA-256 hash of the canonical VK encoding (optional, computed lazily if needed)
 */
public record VerificationMaterial(
        byte[] vkBytes,
        ProofSystemId proofSystemId,
        CurveId curveId,
        CircuitId circuitId,
        Optional<byte[]> vkHash
) {

    public VerificationMaterial {
        Objects.requireNonNull(vkBytes, "vk bytes must not be null");
        if (vkBytes.length == 0) {
            throw new IllegalArgumentException("vk bytes must not be empty");
        }
        Objects.requireNonNull(proofSystemId, "proof system id must not be null");
        Objects.requireNonNull(curveId, "curve id must not be null");
        Objects.requireNonNull(circuitId, "circuit id must not be null");
        Objects.requireNonNull(vkHash, "vkHash optional must not be null");
        vkBytes = vkBytes.clone();
        vkHash = vkHash.map(byte[]::clone);
    }

    @Override
    public byte[] vkBytes() {
        return vkBytes.clone();
    }

    @Override
    public Optional<byte[]> vkHash() {
        return vkHash.map(byte[]::clone);
    }

    /**
     * Create verification material without a pre-computed hash.
     */
    public static VerificationMaterial of(byte[] vkBytes, ProofSystemId proofSystem, CurveId curve, CircuitId circuit) {
        return new VerificationMaterial(vkBytes, proofSystem, curve, circuit, Optional.empty());
    }

    /**
     * Create verification material with a pre-computed VK hash.
     */
    public static VerificationMaterial of(byte[] vkBytes, ProofSystemId proofSystem, CurveId curve, CircuitId circuit, byte[] vkHash) {
        return new VerificationMaterial(vkBytes, proofSystem, curve, circuit, Optional.of(vkHash));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof VerificationMaterial m
                && Arrays.equals(vkBytes, m.vkBytes)
                && proofSystemId == m.proofSystemId
                && curveId == m.curveId
                && circuitId.equals(m.circuitId)
                && optionalBytesEqual(vkHash, m.vkHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(vkBytes), proofSystemId, curveId, circuitId);
    }

    private static boolean optionalBytesEqual(Optional<byte[]> a, Optional<byte[]> b) {
        if (a.isEmpty() && b.isEmpty()) return true;
        if (a.isEmpty() || b.isEmpty()) return false;
        return Arrays.equals(a.get(), b.get());
    }
}
