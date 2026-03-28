package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Codec for snarkjs PlonK JSON proof files (proof.json, verification_key.json).
 *
 * <p>Follows the same pattern as {@link SnarkjsJsonCodec} but for PlonK-specific fields.</p>
 *
 * <p>snarkjs PlonK proof.json format includes:
 * A, B, C (wire commitments), Z (permutation), T1-T3 (quotient),
 * eval_a, eval_b, eval_c, eval_s1, eval_s2, eval_zw (evaluations),
 * Wxi, Wxiw (opening proofs), protocol, curve.</p>
 */
public final class SnarkjsPlonkCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SnarkjsPlonkCodec() {}

    // --- Proof parsing ---

    public static SnarkjsPlonkProof parseProof(Path path) {
        try {
            return parseProof(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK proof file: " + path, e);
        }
    }

    public static SnarkjsPlonkProof parseProof(InputStream in) {
        try {
            return parseProof(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK proof input stream", e);
        }
    }

    public static SnarkjsPlonkProof parseProof(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);

            return new SnarkjsPlonkProof(
                    parseG1(root, "A"),
                    parseG1(root, "B"),
                    parseG1(root, "C"),
                    parseG1(root, "Z"),
                    parseG1(root, "T1"),
                    parseG1(root, "T2"),
                    parseG1(root, "T3"),
                    parseScalar(root, "eval_a"),
                    parseScalar(root, "eval_b"),
                    parseScalar(root, "eval_c"),
                    parseScalar(root, "eval_s1"),
                    parseScalar(root, "eval_s2"),
                    parseScalar(root, "eval_zw"),
                    parseG1(root, "Wxi"),
                    parseG1(root, "Wxiw"),
                    root.has("protocol") ? root.get("protocol").asText() : "plonk",
                    root.has("curve") ? root.get("curve").asText() : "bn128"
            );
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to parse PlonK proof JSON", e);
        }
    }

    // --- Verification key parsing ---

    public static SnarkjsPlonkVerificationKey parseVerificationKey(Path path) {
        try {
            return parseVerificationKey(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK VK file: " + path, e);
        }
    }

    public static SnarkjsPlonkVerificationKey parseVerificationKey(InputStream in) {
        try {
            return parseVerificationKey(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK VK input stream", e);
        }
    }

    public static SnarkjsPlonkVerificationKey parseVerificationKey(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);

            return new SnarkjsPlonkVerificationKey(
                    root.has("protocol") ? root.get("protocol").asText() : "plonk",
                    root.has("curve") ? root.get("curve").asText() : "bn128",
                    root.get("nPublic").asInt(),
                    root.get("power").asInt(),
                    new BigInteger(root.get("k1").asText()),
                    new BigInteger(root.get("k2").asText()),
                    parseG1(root, "Qm"),
                    parseG1(root, "Ql"),
                    parseG1(root, "Qr"),
                    parseG1(root, "Qo"),
                    parseG1(root, "Qc"),
                    parseG1(root, "S1"),
                    parseG1(root, "S2"),
                    parseG1(root, "S3"),
                    parseG2(root, "X_2"),
                    new BigInteger(root.get("w").asText())
            );
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to parse PlonK verification key JSON", e);
        }
    }

    // --- Envelope construction ---

    /**
     * Build a {@link ZkProofEnvelope} from snarkjs PlonK JSON strings.
     */
    public static ZkProofEnvelope toEnvelopeFromJson(String proofJson, String vkJson,
                                                      String publicJson, CircuitId circuitId) {
        var proof = parseProof(proofJson);
        var inputs = SnarkjsJsonCodec.parsePublicInputs(publicJson);

        ProofSystemId proofSystem = ProofSystemId.PLONK;
        CurveId curve = CurveId.fromValue(proof.curve());

        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkHash = SnarkjsJsonCodec.sha256(vkBytes);

        return ZkProofEnvelope.builder()
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .publicInputs(inputs)
                .vkRef(new VerificationKeyRef.ByHash(vkHash))
                .proofFormat("snarkjs-plonk-json")
                .build();
    }

    // --- Internal helpers ---

    private static List<BigInteger> parseG1(JsonNode root, String fieldName) {
        var node = root.get(fieldName);
        if (node == null || !node.isArray()) {
            throw new CodecException("Missing or invalid G1 field: " + fieldName);
        }
        List<BigInteger> coords = new ArrayList<>();
        for (var element : node) {
            coords.add(new BigInteger(element.asText()));
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG2(JsonNode root, String fieldName) {
        var node = root.get(fieldName);
        if (node == null || !node.isArray()) {
            throw new CodecException("Missing or invalid G2 field: " + fieldName);
        }
        List<List<BigInteger>> coords = new ArrayList<>();
        for (var element : node) {
            List<BigInteger> pair = new ArrayList<>();
            for (var e : element) {
                pair.add(new BigInteger(e.asText()));
            }
            coords.add(pair);
        }
        return coords;
    }

    private static BigInteger parseScalar(JsonNode root, String fieldName) {
        var node = root.get(fieldName);
        if (node == null) {
            throw new CodecException("Missing scalar field: " + fieldName);
        }
        return new BigInteger(node.asText());
    }
}
