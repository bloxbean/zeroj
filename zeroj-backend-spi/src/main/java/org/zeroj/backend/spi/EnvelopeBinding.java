package org.zeroj.backend.spi;

import org.zeroj.api.VerificationKeyRef;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.VerificationResult;
import org.zeroj.api.ZkProofEnvelope;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Optional;

/**
 * Shared envelope-to-verification-material binding checks enforced centrally by
 * {@link org.zeroj.verifier.core.VerifierOrchestrator} and defensively by concrete
 * {@link ZkVerifier} backends (ADR-0067).
 *
 * <p>Validates envelope version, proof system, curve, circuit identifier, and SHA-256
 * verification-key digest consistency without assuming any proof-system-specific key encoding
 * or rejecting empty {@code publicInputs} (which are valid for BBS and zero-input circuits).</p>
 */
public final class EnvelopeBinding {

    private EnvelopeBinding() {}

    /**
     * Validate that {@code envelope} and {@code material} are structurally consistent and
     * bound to the same statement and verification key bytes.
     *
     * @return {@link Optional#empty()} if all binding invariants hold, otherwise the
     *         {@link VerificationResult} describing the failure
     */
    public static Optional<VerificationResult> validateBinding(
            ZkProofEnvelope envelope,
            VerificationMaterial material) {
        if (envelope == null) {
            return Optional.of(VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Proof envelope must not be null"));
        }
        if (envelope.version() < 1 || envelope.version() > ZkProofEnvelope.currentVersion()) {
            return Optional.of(VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Unsupported proof envelope version: " + envelope.version()));
        }
        if (material == null) {
            return Optional.of(VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Verification material must not be null"));
        }
        if (material.proofSystemId() != envelope.proofSystem()
                || material.curveId() != envelope.curve()
                || !material.circuitId().equals(envelope.circuitId())) {
            return Optional.of(VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Verification material does not match proof envelope"));
        }

        byte[] actualVkHash = sha256(material.vkBytes());
        if (material.vkHash().isPresent()
                && !Arrays.equals(material.vkHash().orElseThrow(), actualVkHash)) {
            return Optional.of(VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Verification material hash does not match VK bytes"));
        }
        if (envelope.vkRef() instanceof VerificationKeyRef.ByHash byHash
                && !Arrays.equals(byHash.hash(), actualVkHash)) {
            return Optional.of(VerificationResult.error(
                    VerificationResult.ReasonCode.VK_MISMATCH,
                    "Proof envelope VK hash does not match verification material"));
        }
        return Optional.empty();
    }

    /**
     * Compute the SHA-256 digest of {@code data}.
     */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
