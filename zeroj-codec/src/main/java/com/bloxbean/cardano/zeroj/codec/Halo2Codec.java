package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Codec for Halo2 proof artifacts (IPA on Pasta curves, KZG on BLS12-381).
 * <p>
 * Parses the JSON format produced by the zeroj-halo2 Rust library into ZeroJ model types.
 * The Halo2 result JSON contains base64-encoded proof, params, and public inputs.
 * <p>
 * Halo2 result JSON format:
 * <pre>{@code
 * {
 *   "protocol": "halo2",
 *   "curve": "pallas",
 *   "commitmentScheme": "IPA",
 *   "trustedSetup": false,
 *   "proof": "<base64>",
 *   "params": "<base64>",
 *   "publicInputs": ["33"],
 *   "verified": true
 * }
 * }</pre>
 */
public final class Halo2Codec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Halo2Codec() {}

    /**
     * Build a {@link ZkProofEnvelope} from a Halo2 result JSON string.
     * <p>
     * The entire result JSON is stored as the proof bytes in the envelope.
     * The verifier extracts proof and params from the JSON at verification time.
     *
     * @param resultJson the full Halo2 result JSON (contains proof, params, public inputs)
     * @param circuitId  the circuit identifier
     * @return a fully populated proof envelope with ProofSystemId.HALO2
     */
    public static ZkProofEnvelope toEnvelopeFromJson(String resultJson, CircuitId circuitId) {
        try {
            JsonNode root = MAPPER.readTree(resultJson);

            CurveId curve = detectCurve(root);
            PublicInputs inputs = parsePublicInputs(root);

            byte[] proofBytes = resultJson.getBytes(StandardCharsets.UTF_8);
            byte[] vkHash = SnarkjsJsonCodec.sha256(proofBytes);

            return ZkProofEnvelope.builder()
                    .proofSystem(ProofSystemId.HALO2)
                    .curve(curve)
                    .circuitId(circuitId)
                    .proofBytes(proofBytes)
                    .publicInputs(inputs)
                    .vkRef(new VerificationKeyRef.ByHash(vkHash))
                    .proofFormat("halo2-ipa-json")
                    .build();
        } catch (Exception e) {
            throw new CodecException("Failed to parse Halo2 result JSON", e);
        }
    }

    /**
     * Build a {@link ZkProofEnvelope} from separate Halo2 JSON components.
     *
     * @param resultJson the full result JSON (with proof + params base64)
     * @param publicJson the public inputs JSON array (decimal strings)
     * @param circuitId  the circuit identifier
     * @return a fully populated proof envelope
     */
    public static ZkProofEnvelope toEnvelopeFromJson(String resultJson, String publicJson,
                                                      CircuitId circuitId) {
        try {
            PublicInputs inputs = SnarkjsJsonCodec.parsePublicInputs(publicJson);
            JsonNode root = MAPPER.readTree(resultJson);
            CurveId curve = detectCurve(root);

            byte[] proofBytes = resultJson.getBytes(StandardCharsets.UTF_8);
            byte[] vkHash = SnarkjsJsonCodec.sha256(proofBytes);

            return ZkProofEnvelope.builder()
                    .proofSystem(ProofSystemId.HALO2)
                    .curve(curve)
                    .circuitId(circuitId)
                    .proofBytes(proofBytes)
                    .publicInputs(inputs)
                    .vkRef(new VerificationKeyRef.ByHash(vkHash))
                    .proofFormat("halo2-ipa-json")
                    .build();
        } catch (Exception e) {
            throw new CodecException("Failed to parse Halo2 components", e);
        }
    }

    /**
     * Extract the protocol identifier from Halo2 result JSON.
     */
    public static String extractProtocol(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            return root.has("protocol") ? root.get("protocol").asText() : "halo2";
        } catch (Exception e) {
            return "halo2";
        }
    }

    /**
     * Check if a Halo2 result indicates the proof was verified during generation.
     */
    public static boolean wasVerified(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            return root.has("verified") && root.get("verified").asBoolean();
        } catch (Exception e) {
            return false;
        }
    }

    private static CurveId detectCurve(JsonNode root) {
        if (root.has("curve")) {
            String curve = root.get("curve").asText();
            try {
                return CurveId.fromValue(curve);
            } catch (IllegalArgumentException e) {
                // Fall through to default
            }
        }
        return CurveId.PALLAS; // default for Halo2 IPA
    }

    private static PublicInputs parsePublicInputs(JsonNode root) {
        if (!root.has("publicInputs")) {
            return new PublicInputs(List.of());
        }
        JsonNode piNode = root.get("publicInputs");
        if (!piNode.isArray()) {
            return new PublicInputs(List.of());
        }
        List<BigInteger> values = new ArrayList<>();
        for (JsonNode element : piNode) {
            values.add(new BigInteger(element.asText()));
        }
        return new PublicInputs(values);
    }
}
