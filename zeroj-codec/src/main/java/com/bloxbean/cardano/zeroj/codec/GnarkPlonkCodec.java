package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Codec for gnark PlonK proof artifacts.
 * <p>
 * Parses gnark's PlonK JSON format (proof.json, public.json) into ZeroJ model types.
 * gnark PlonK proofs use a different structure than snarkjs Groth16:
 * <ul>
 *   <li>Proof is a binary blob (base64-encoded) — not individual curve point coordinates</li>
 *   <li>VK is also a binary blob or structured JSON with decomposed G1/G2 points</li>
 *   <li>Public inputs are decimal strings in a JSON array (same as snarkjs)</li>
 * </ul>
 * <p>
 * gnark proof.json format:
 * <pre>{@code
 * {"binary":"<base64>","protocol":"plonk","curve":"bls12381","hex":"<hex>"}
 * }</pre>
 */
public final class GnarkPlonkCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private GnarkPlonkCodec() {}

    /**
     * Build a {@link ZkProofEnvelope} from gnark PlonK JSON strings.
     * <p>
     * The proof bytes in the envelope contain the original gnark proof JSON.
     * The VK bytes contain the raw VK JSON (binary + metadata).
     *
     * @param proofJson  gnark proof.json content (with "binary" and "protocol" fields)
     * @param vkJson     gnark verification_key.json content
     * @param publicJson public.json content (decimal string array)
     * @param circuitId  the circuit identifier
     * @return a fully populated proof envelope with ProofSystemId.PLONK
     */
    public static ZkProofEnvelope toEnvelopeFromJson(String proofJson, String vkJson,
                                                      String publicJson, CircuitId circuitId) {
        CurveId curve = detectCurve(proofJson);
        PublicInputs inputs = parsePublicInputs(publicJson);

        byte[] proofBytes = proofJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkHash = SnarkjsJsonCodec.sha256(vkBytes);

        return ZkProofEnvelope.builder()
                .proofSystem(ProofSystemId.PLONK)
                .curve(curve)
                .circuitId(circuitId)
                .proofBytes(proofBytes)
                .publicInputs(inputs)
                .vkRef(new VerificationKeyRef.ByHash(vkHash))
                .proofFormat("gnark-plonk-json")
                .build();
    }

    /**
     * Parse public inputs from a JSON array of decimal strings.
     * Compatible with both snarkjs and gnark public.json format.
     */
    public static PublicInputs parsePublicInputs(String json) {
        return SnarkjsJsonCodec.parsePublicInputs(json);
    }

    /**
     * Extract the base64-encoded proof binary from gnark's proof JSON.
     *
     * @param proofJson gnark proof.json content
     * @return base64 string of the proof binary
     */
    public static String extractProofBase64(String proofJson) {
        try {
            JsonNode root = MAPPER.readTree(proofJson);
            if (root.has("binary")) {
                return root.get("binary").asText();
            }
            throw new CodecException("gnark proof JSON missing 'binary' field");
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to parse gnark proof JSON", e);
        }
    }

    /**
     * Extract the protocol identifier from gnark proof/VK JSON.
     */
    public static String extractProtocol(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            return root.has("protocol") ? root.get("protocol").asText() : "plonk";
        } catch (Exception e) {
            return "plonk";
        }
    }

    private static CurveId detectCurve(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            if (root.has("curve")) {
                String curve = root.get("curve").asText();
                return CurveId.fromValue(curve);
            }
        } catch (Exception ignored) {}
        return CurveId.BLS12_381; // default for gnark PlonK
    }
}
