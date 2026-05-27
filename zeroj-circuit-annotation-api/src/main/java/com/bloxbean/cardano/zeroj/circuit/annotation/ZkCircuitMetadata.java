package com.bloxbean.cardano.zeroj.circuit.annotation;

import com.bloxbean.cardano.zeroj.api.CircuitId;
import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;
import com.bloxbean.cardano.zeroj.api.PublicInputs;
import com.bloxbean.cardano.zeroj.api.VerificationKeyRef;
import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Stable circuit identity and proof-envelope metadata for generated annotated
 * circuits. Circuit IDs are name-based; the author-controlled circuit version
 * is carried separately in envelope metadata so deployments can choose name-only
 * or name-plus-version key lookup policies.
 */
public record ZkCircuitMetadata(
        CircuitId circuitId,
        String circuitName,
        int circuitVersion,
        Map<String, String> parameters) {

    public static final String CIRCUIT_NAME_KEY = "zeroj.circuit.name";
    public static final String CIRCUIT_VERSION_KEY = "zeroj.circuit.version";
    public static final String CIRCUIT_PARAM_PREFIX = "zeroj.circuit.param.";

    public ZkCircuitMetadata {
        Objects.requireNonNull(circuitId, "circuitId");
        Objects.requireNonNull(circuitName, "circuitName");
        if (circuitVersion <= 0) {
            throw new IllegalArgumentException("circuitVersion must be positive");
        }
        parameters = Collections.unmodifiableMap(new LinkedHashMap<>(
                Objects.requireNonNull(parameters, "parameters")));
    }

    public static ZkCircuitMetadata of(ZkCircuitSchema schema, int circuitVersion) {
        Objects.requireNonNull(schema, "schema");
        var params = new LinkedHashMap<String, String>();
        for (ZkCircuitSchema.Parameter parameter : schema.parameters()) {
            params.put(parameter.name(), parameter.value());
        }
        return new ZkCircuitMetadata(
                new CircuitId(schema.name()),
                schema.name(),
                circuitVersion,
                params);
    }

    public Map<String, String> envelopeMetadata() {
        var out = new LinkedHashMap<String, String>();
        out.put(CIRCUIT_NAME_KEY, circuitName);
        out.put(CIRCUIT_VERSION_KEY, Integer.toString(circuitVersion));
        parameters.forEach((name, value) -> out.put(CIRCUIT_PARAM_PREFIX + name, value));
        return Collections.unmodifiableMap(out);
    }

    public ZkProofEnvelope.Builder proofEnvelopeBuilder(
            ProofSystemId proofSystem,
            CurveId curve,
            byte[] proofBytes,
            PublicInputs publicInputs,
            VerificationKeyRef vkRef) {
        return ZkProofEnvelope.builder()
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .proofBytes(proofBytes)
                .publicInputs(publicInputs)
                .vkRef(vkRef)
                .metadata(envelopeMetadata());
    }
}
