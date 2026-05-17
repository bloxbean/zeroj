package com.bloxbean.cardano.zeroj.examples.annotation;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSSerializer;
import com.bloxbean.cardano.zeroj.examples.dsl.common.GnarkProverHelper;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.prover.wasm.WitnessExporter;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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

    public GnarkProver.FullProveResponse generateGroth16ProofNative(
            BigInteger age,
            BigInteger threshold,
            GnarkProver prover) {
        var inputs = inputs(age, threshold);
        return GnarkProverHelper.groth16Prove(
                AnnotatedAgeVerificationCircuit.build(),
                inputs.toWitnessMap(),
                curve,
                prover);
    }

    public ZkProofEnvelope toEnvelope(
            GnarkProver.FullProveResponse proof,
            AnnotatedAgeVerificationCircuit.Inputs inputs,
            VerificationKeyRef vkRef) {
        Objects.requireNonNull(proof, "proof");
        Objects.requireNonNull(inputs, "inputs");
        CurveId responseCurve = CurveId.fromValue(proof.proveResponse().curve());
        if (responseCurve != curve) {
            throw new IllegalArgumentException("proof curve does not match helper curve");
        }
        if (!proof.proveResponse().publicSignals().equals(inputs.publicValues())) {
            throw new IllegalArgumentException("proof public signals do not match generated public inputs");
        }
        return AnnotatedAgeVerificationCircuit.proofEnvelopeBuilder(
                        AnnotatedAgeVerificationCircuit.build(),
                        ProofSystemId.fromValue(proof.proveResponse().protocol()),
                        responseCurve,
                        proof.proveResponse().proofJson().getBytes(StandardCharsets.UTF_8),
                        inputs,
                        vkRef)
                .build();
    }
}
