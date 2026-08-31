package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSSerializer;
import com.bloxbean.cardano.zeroj.examples.dsl.common.WitnessExporter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * Phase 9 proof-flow helper showing how generated annotated companions plug
 * into the existing compiler, witness, prover, and proof-envelope APIs.
 */
public final class AnnotatedAgeVerificationProofHelper {
    private final CurveId curve;

    public AnnotatedAgeVerificationProofHelper(CurveId curve) {
        this.curve = Objects.requireNonNull(curve, "curve");
    }

    public AnnotatedAgeVerificationCircuit.Inputs inputs(BigInteger age, BigInteger threshold) {
        return AnnotatedAgeVerificationCircuit.inputs()
                .age(age)
                .threshold(threshold);
    }

    public byte[] generateR1CS() {
        var circuit = AnnotatedAgeVerificationCircuit.build();
        return R1CSSerializer.serialize(circuit.compileR1CS(curve));
    }

    public BigInteger[] calculateWitness(BigInteger age, BigInteger threshold) {
        var circuit = AnnotatedAgeVerificationCircuit.build();
        var inputs = inputs(age, threshold);
        return AnnotatedAgeVerificationCircuit.calculateWitness(circuit, inputs, curve);
    }

    public byte[] generateWitnessBytes(BigInteger age, BigInteger threshold) {
        var config = FieldConfig.forCurve(curve);
        return WitnessExporter.toWtns(calculateWitness(age, threshold), config.prime(), config.n32());
    }

    /**
     * Prover-neutral view of what a prover returns for one proof.
     *
     * <p>ADR-0044 removed {@code zeroj-prover-gnark} and its {@code ProveResponse} type. This
     * record replaces it verbatim in shape so the public-input and curve binding checks below —
     * the reason this helper is an assurance fixture rather than a demo — are unchanged.</p>
     *
     * @param proofJson     the prover's proof document
     * @param publicSignals the public signals the prover emitted, in prover order
     * @param protocol      the proof-system id string, e.g. {@code groth16}
     * @param curve         the curve id string the prover reported
     */
    public record ProverOutput(String proofJson,
                               List<BigInteger> publicSignals,
                               String protocol,
                               String curve) {
    }

    /**
     * Binds a prover's output to a {@link ZkProofEnvelope}, rejecting any proof whose reported
     * curve or public signals disagree with the inputs the circuit companion generated.
     */
    public ZkProofEnvelope toEnvelope(
            ProverOutput proof,
            AnnotatedAgeVerificationCircuit.Inputs inputs,
            VerificationKeyRef vkRef) {
        Objects.requireNonNull(proof, "proof");
        Objects.requireNonNull(inputs, "inputs");
        CurveId responseCurve = CurveId.fromValue(proof.curve());
        if (responseCurve != curve) {
            throw new IllegalArgumentException("proof curve does not match helper curve");
        }
        if (!proof.publicSignals().equals(inputs.publicValues())) {
            throw new IllegalArgumentException("proof public signals do not match generated public inputs");
        }
        return AnnotatedAgeVerificationCircuit.proofEnvelopeBuilder(
                        AnnotatedAgeVerificationCircuit.build(),
                        ProofSystemId.fromValue(proof.protocol()),
                        responseCurve,
                        proof.proofJson().getBytes(StandardCharsets.UTF_8),
                        inputs,
                        vkRef)
                .build();
    }
}
