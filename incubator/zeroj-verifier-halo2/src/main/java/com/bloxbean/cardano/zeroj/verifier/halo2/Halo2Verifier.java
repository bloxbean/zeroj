package com.bloxbean.cardano.zeroj.verifier.halo2;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Halo2 IPA verifier that delegates to the Rust native library via FFM.
 * <p>
 * Implements the {@link ZkVerifier} SPI so Halo2 proofs can route through
 * {@link com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator}.
 * <p>
 * <b>Key advantage:</b> Halo2 IPA uses NO trusted setup. The commitment parameters
 * are transparent (deterministic, publicly verifiable).
 * <p>
 * <b>Requirements:</b>
 * <ul>
 *   <li>Halo2 Rust native library must be available at runtime</li>
 *   <li>Proof bytes must contain the Halo2 result JSON (with "proof" and "params" base64 fields)</li>
 *   <li>VK is regenerated from params at verify time (zcash halo2 v0.3 removed VK serialization)</li>
 * </ul>
 */
public class Halo2Verifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.HALO2, CurveId.PALLAS, "halo2-ipa-rust");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Halo2Library library;

    public Halo2Verifier() {
        // Lazy init
    }

    public Halo2Verifier(Halo2Library library) {
        this.library = library;
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            if (library == null) {
                library = new Halo2Library();
            }

            // Parse the proof JSON (contains base64-encoded proof, params, public inputs)
            String proofJson = new String(envelope.proofBytes(), StandardCharsets.UTF_8);
            JsonNode root = MAPPER.readTree(proofJson);

            // Extract base64-encoded fields
            byte[] proofBytes = Base64.getDecoder().decode(root.get("proof").asText());
            byte[] paramsBytes = Base64.getDecoder().decode(root.get("params").asText());

            // Build public inputs JSON array from envelope
            List<String> piStrings = envelope.publicInputs().values().stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
            String piJson = MAPPER.writeValueAsString(piStrings);

            // Verify via Rust FFM
            boolean valid = library.verify(paramsBytes, new byte[0], proofBytes, piJson);

            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("Halo2 IPA verification failed");
        } catch (Exception e) {
            return VerificationResult.error(VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "Halo2 verification error: " + e.getMessage());
        }
    }

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }
}
