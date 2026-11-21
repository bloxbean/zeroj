package org.zeroj.verifier.core;

import org.zeroj.api.VerificationMaterial;
import org.zeroj.api.VerificationResult;
import org.zeroj.api.ZkProofEnvelope;
import org.zeroj.backend.spi.EnvelopeBinding;
import org.zeroj.backend.spi.VerificationKeyRegistry;
import org.zeroj.backend.spi.ZkVerifier;

import java.util.Objects;

/**
 * Routes proof verification requests to the correct backend based on proof system and curve.
 *
 * <p>This is the main entry point for verifying proofs. It resolves the verification key
 * from the registry, checks envelope-to-material binding (ADR-0067), finds the appropriate
 * backend, and delegates verification.</p>
 */
public class VerifierOrchestrator {

    private final VerifierRegistry registry;
    private final VerificationKeyRegistry vkRegistry;

    public VerifierOrchestrator(VerifierRegistry registry, VerificationKeyRegistry vkRegistry) {
        this.registry = Objects.requireNonNull(registry);
        this.vkRegistry = Objects.requireNonNull(vkRegistry);
    }

    /**
     * Verify a proof envelope using the registered backends.
     *
     * <p>Steps:</p>
     * <ol>
     *   <li>Validate envelope presence and version</li>
     *   <li>Resolve the verification key from the VK registry</li>
     *   <li>Validate envelope-to-material binding (proof system, curve, circuit id, VK hash)</li>
     *   <li>Find a backend that supports the proof's system + curve</li>
     *   <li>Delegate cryptographic verification to the backend</li>
     * </ol>
     */
    public VerificationResult verify(ZkProofEnvelope envelope) {
        if (envelope == null) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Proof envelope must not be null");
        }
        if (envelope.version() < 1 || envelope.version() > ZkProofEnvelope.currentVersion()) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                    "Unsupported proof envelope version: " + envelope.version());
        }

        // Resolve VK
        var material = vkRegistry.lookup(envelope.vkRef());
        if (material.isEmpty()) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNKNOWN_VERIFICATION_KEY,
                    "Verification key not found: " + envelope.vkRef());
        }

        return verify(envelope, material.get());
    }

    /**
     * Verify a proof envelope with an explicitly provided verification material.
     */
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        var bindingError = EnvelopeBinding.validateBinding(envelope, material);
        if (bindingError.isPresent()) {
            return bindingError.get();
        }

        // Find backend
        var verifier = registry.find(envelope.proofSystem(), envelope.curve());
        if (verifier.isEmpty()) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.UNSUPPORTED_PROOF_SYSTEM,
                    "No backend for " + envelope.proofSystem() + "/" + envelope.curve());
        }

        return verifier.get().verify(envelope, material);
    }
}
