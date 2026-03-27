package com.bloxbean.cardano.zeroj.patterns.statetransition;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.VerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;

import java.util.Objects;

/**
 * Verifies a {@link StateTransition} against a registered verification key.
 *
 * <p>This wraps the low-level {@link VerifierOrchestrator} with a typed API
 * specific to the state transition pattern.</p>
 */
public class StateTransitionVerifier {

    private final VerifierOrchestrator orchestrator;
    private final VerificationKeyRegistry vkRegistry;

    public StateTransitionVerifier(VerifierOrchestrator orchestrator, VerificationKeyRegistry vkRegistry) {
        this.orchestrator = Objects.requireNonNull(orchestrator);
        this.vkRegistry = vkRegistry; // nullable — not needed when using verify(transition, material)
    }

    public StateTransitionVerifier(VerifierOrchestrator orchestrator) {
        this(orchestrator, null);
    }

    /**
     * Verify a state transition, returning an enriched result with transition metadata.
     */
    public StateTransitionResult verifyTransition(StateTransition transition, VerificationMaterial material) {
        var result = verify(transition, material);
        return StateTransitionResult.from(result, transition);
    }

    /**
     * Verify a state transition.
     *
     * @param transition the state transition to verify
     * @return verification result
     */
    public VerificationResult verify(StateTransition transition) {
        var envelope = buildEnvelope(transition);
        return orchestrator.verify(envelope);
    }

    /**
     * Verify a state transition with explicitly provided verification material.
     */
    public VerificationResult verify(StateTransition transition, VerificationMaterial material) {
        var envelope = buildEnvelope(transition);
        return orchestrator.verify(envelope, material);
    }

    private ZkProofEnvelope buildEnvelope(StateTransition transition) {
        return ZkProofEnvelope.builder()
                .proofSystem(transition.proofSystem())
                .curve(transition.curve())
                .circuitId(new CircuitId(transition.circuitId()))
                .proofBytes(transition.proofBytes())
                .publicInputs(new PublicInputs(transition.allPublicInputs()))
                .vkRef(new VerificationKeyRef.ById(transition.circuitId()))
                .build();
    }
}
