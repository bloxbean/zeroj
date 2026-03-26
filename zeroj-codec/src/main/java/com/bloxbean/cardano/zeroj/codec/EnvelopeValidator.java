package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;

import java.util.ArrayList;
import java.util.List;

/**
 * Validates a {@link ZkProofEnvelope} for structural correctness.
 *
 * <p>This validates the envelope structure, not the cryptographic proof itself.
 * Cryptographic verification is done by the backend verifier.</p>
 */
public final class EnvelopeValidator {

    private EnvelopeValidator() {}

    /**
     * Validate an envelope and return a list of validation errors.
     * An empty list means the envelope is valid.
     */
    public static List<String> validate(ZkProofEnvelope envelope) {
        List<String> errors = new ArrayList<>();

        if (envelope.version() < 1) {
            errors.add("version must be >= 1, got " + envelope.version());
        }

        if (envelope.version() > ZkProofEnvelope.currentVersion()) {
            errors.add("unsupported envelope version " + envelope.version()
                    + " (max supported: " + ZkProofEnvelope.currentVersion() + ")");
        }

        if (envelope.proofBytes().length == 0) {
            errors.add("proofBytes must not be empty");
        }

        if (envelope.publicInputs().values().isEmpty()) {
            errors.add("publicInputs must not be empty");
        }

        return List.copyOf(errors);
    }

    /**
     * Validate and throw if the envelope is structurally invalid.
     *
     * @throws CodecException if validation fails
     */
    public static void requireValid(ZkProofEnvelope envelope) {
        List<String> errors = validate(envelope);
        if (!errors.isEmpty()) {
            throw new CodecException("Invalid envelope: " + String.join("; ", errors));
        }
    }
}
