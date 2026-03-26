package com.bloxbean.cardano.zeroj.patterns;

import com.bloxbean.cardano.zeroj.api.VerificationMaterial;
import com.bloxbean.cardano.zeroj.api.VerificationResult;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * Composable verification policy that chains crypto verification with domain-specific rules.
 *
 * <p>Usage:</p>
 * <pre>{@code
 * var policy = VerificationPolicyTemplate.create(orchestrator)
 *     .requireProofSystem(ProofSystemId.GROTH16)
 *     .requireCurve(CurveId.BN254)
 *     .addRule("min-public-inputs", envelope ->
 *         envelope.publicInputs().size() >= 2
 *             ? null
 *             : "At least 2 public inputs required")
 *     .build();
 *
 * var result = policy.evaluate(envelope, material);
 * }</pre>
 */
public final class VerificationPolicyTemplate {

    private final VerifierOrchestrator orchestrator;
    private final List<PolicyRule> preRules;
    private final List<PolicyRule> postRules;

    private VerificationPolicyTemplate(VerifierOrchestrator orchestrator,
                                        List<PolicyRule> preRules,
                                        List<PolicyRule> postRules) {
        this.orchestrator = orchestrator;
        this.preRules = List.copyOf(preRules);
        this.postRules = List.copyOf(postRules);
    }

    /**
     * Evaluate the policy: run pre-rules, then crypto verification, then post-rules.
     */
    public VerificationResult evaluate(ZkProofEnvelope envelope, VerificationMaterial material) {
        // Pre-verification rules
        for (var rule : preRules) {
            String error = rule.check().apply(envelope);
            if (error != null) {
                return VerificationResult.policyRejected(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        rule.name() + ": " + error);
            }
        }

        // Crypto verification
        var cryptoResult = orchestrator.verify(envelope, material);
        if (!cryptoResult.proofValid()) {
            return cryptoResult;
        }

        // Post-verification rules
        for (var rule : postRules) {
            String error = rule.check().apply(envelope);
            if (error != null) {
                return VerificationResult.policyRejected(
                        VerificationResult.ReasonCode.MALFORMED_ENVELOPE,
                        rule.name() + ": " + error);
            }
        }

        return VerificationResult.ok();
    }

    public static Builder create(VerifierOrchestrator orchestrator) {
        return new Builder(orchestrator);
    }

    public static final class Builder {
        private final VerifierOrchestrator orchestrator;
        private final List<PolicyRule> preRules = new ArrayList<>();
        private final List<PolicyRule> postRules = new ArrayList<>();

        private Builder(VerifierOrchestrator orchestrator) {
            this.orchestrator = Objects.requireNonNull(orchestrator);
        }

        /**
         * Add a rule that runs BEFORE crypto verification (cheap checks first).
         *
         * @param name  rule name (for error messages)
         * @param check function that returns null if OK, or an error message string
         */
        public Builder addPreRule(String name, Function<ZkProofEnvelope, String> check) {
            preRules.add(new PolicyRule(name, check));
            return this;
        }

        /**
         * Add a rule that runs AFTER crypto verification (e.g., business logic).
         */
        public Builder addPostRule(String name, Function<ZkProofEnvelope, String> check) {
            postRules.add(new PolicyRule(name, check));
            return this;
        }

        /**
         * Convenience: require a specific proof system.
         */
        public Builder requireProofSystem(com.bloxbean.cardano.zeroj.api.ProofSystemId expected) {
            return addPreRule("proof-system-check", e ->
                    e.proofSystem() == expected ? null : "Expected " + expected + ", got " + e.proofSystem());
        }

        /**
         * Convenience: require a specific curve.
         */
        public Builder requireCurve(com.bloxbean.cardano.zeroj.api.CurveId expected) {
            return addPreRule("curve-check", e ->
                    e.curve() == expected ? null : "Expected " + expected + ", got " + e.curve());
        }

        /**
         * Convenience: require minimum number of public inputs.
         */
        public Builder requireMinPublicInputs(int min) {
            return addPreRule("min-public-inputs", e ->
                    e.publicInputs().size() >= min ? null : "Need >= " + min + " public inputs, got " + e.publicInputs().size());
        }

        public VerificationPolicyTemplate build() {
            return new VerificationPolicyTemplate(orchestrator, preRules, postRules);
        }
    }

    private record PolicyRule(String name, Function<ZkProofEnvelope, String> check) {}
}
