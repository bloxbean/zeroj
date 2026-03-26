package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Codec for snarkjs JSON proof files (proof.json, verification_key.json, public.json).
 *
 * <p>Parses the snarkjs Groth16 JSON format into ZeroJ model types.</p>
 */
public final class SnarkjsJsonCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SnarkjsJsonCodec() {}

    // --- Proof parsing ---

    /**
     * Parse a snarkjs proof.json file.
     */
    public static SnarkjsProof parseProof(Path path) {
        try {
            return parseProof(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read proof file: " + path, e);
        }
    }

    /**
     * Parse a snarkjs proof.json from an input stream.
     */
    public static SnarkjsProof parseProof(InputStream in) {
        try {
            return parseProof(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read proof input stream", e);
        }
    }

    /**
     * Parse a snarkjs proof.json from a JSON string.
     */
    public static SnarkjsProof parseProof(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            requireField(root, "pi_a", "proof");
            requireField(root, "pi_b", "proof");
            requireField(root, "pi_c", "proof");
            requireField(root, "protocol", "proof");
            requireField(root, "curve", "proof");

            List<BigInteger> piA = parseG1Point(root.get("pi_a"));
            List<List<BigInteger>> piB = parseG2Point(root.get("pi_b"));
            List<BigInteger> piC = parseG1Point(root.get("pi_c"));
            String protocol = root.get("protocol").asText();
            String curve = root.get("curve").asText();

            return new SnarkjsProof(piA, piB, piC, protocol, curve);
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to parse proof JSON", e);
        }
    }

    // --- Verification key parsing ---

    /**
     * Parse a snarkjs verification_key.json file.
     */
    public static SnarkjsVerificationKey parseVerificationKey(Path path) {
        try {
            return parseVerificationKey(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read verification key file: " + path, e);
        }
    }

    /**
     * Parse a snarkjs verification_key.json from an input stream.
     */
    public static SnarkjsVerificationKey parseVerificationKey(InputStream in) {
        try {
            return parseVerificationKey(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read verification key input stream", e);
        }
    }

    /**
     * Parse a snarkjs verification_key.json from a JSON string.
     */
    public static SnarkjsVerificationKey parseVerificationKey(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            requireField(root, "protocol", "verification_key");
            requireField(root, "curve", "verification_key");
            requireField(root, "nPublic", "verification_key");
            requireField(root, "vk_alpha_1", "verification_key");
            requireField(root, "vk_beta_2", "verification_key");
            requireField(root, "vk_gamma_2", "verification_key");
            requireField(root, "vk_delta_2", "verification_key");
            requireField(root, "vk_alphabeta_12", "verification_key");
            requireField(root, "IC", "verification_key");

            String protocol = root.get("protocol").asText();
            String curve = root.get("curve").asText();
            int nPublic = root.get("nPublic").asInt();

            List<BigInteger> vkAlpha1 = parseG1Point(root.get("vk_alpha_1"));
            List<List<BigInteger>> vkBeta2 = parseG2Point(root.get("vk_beta_2"));
            List<List<BigInteger>> vkGamma2 = parseG2Point(root.get("vk_gamma_2"));
            List<List<BigInteger>> vkDelta2 = parseG2Point(root.get("vk_delta_2"));
            List<List<List<BigInteger>>> vkAlphabeta12 = parseGtElement(root.get("vk_alphabeta_12"));
            List<List<BigInteger>> ic = parseG1PointArray(root.get("IC"));

            return new SnarkjsVerificationKey(protocol, curve, nPublic, vkAlpha1,
                    vkBeta2, vkGamma2, vkDelta2, vkAlphabeta12, ic);
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to parse verification key JSON", e);
        }
    }

    // --- Public inputs parsing ---

    /**
     * Parse a snarkjs public.json file into {@link PublicInputs}.
     */
    public static PublicInputs parsePublicInputs(Path path) {
        try {
            return parsePublicInputs(Files.readString(path, StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read public inputs file: " + path, e);
        }
    }

    /**
     * Parse a snarkjs public.json from an input stream.
     */
    public static PublicInputs parsePublicInputs(InputStream in) {
        try {
            return parsePublicInputs(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new CodecException("Failed to read public inputs input stream", e);
        }
    }

    /**
     * Parse a snarkjs public.json from a JSON string.
     */
    public static PublicInputs parsePublicInputs(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            if (!root.isArray()) {
                throw new CodecException("public.json must be a JSON array");
            }
            List<BigInteger> values = new ArrayList<>();
            for (JsonNode element : root) {
                values.add(new BigInteger(element.asText()));
            }
            return new PublicInputs(values);
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to parse public inputs JSON", e);
        }
    }

    // --- Envelope construction ---

    /**
     * Build a {@link ZkProofEnvelope} from parsed snarkjs components.
     *
     * <p>Note: the proof bytes are stored as Jackson-serialized JSON (record field names).
     * Use {@link #toEnvelopeFromJson(String, String, String, CircuitId)} to preserve the
     * original snarkjs JSON format in the envelope.</p>
     *
     * @param proof     parsed snarkjs proof
     * @param vk        parsed snarkjs verification key
     * @param inputs    parsed public inputs
     * @param circuitId the circuit identifier
     * @return a fully populated proof envelope
     */
    public static ZkProofEnvelope toEnvelope(SnarkjsProof proof, SnarkjsVerificationKey vk,
                                              PublicInputs inputs, CircuitId circuitId) {
        ProofSystemId proofSystem = ProofSystemId.fromValue(proof.protocol());
        CurveId curve = CurveId.fromValue(proof.curve());

        byte[] proofBytes = serializeProofToBytes(proof);
        byte[] vkBytes = serializeVkToBytes(vk);
        byte[] vkHash = sha256(vkBytes);

        return ZkProofEnvelope.builder()
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .proofBytes(proofBytes)
                .publicInputs(inputs)
                .vkRef(new VerificationKeyRef.ByHash(vkHash))
                .proofFormat("snarkjs-json")
                .build();
    }

    /**
     * Build a {@link ZkProofEnvelope} from raw snarkjs JSON strings.
     *
     * <p>This preserves the original snarkjs JSON as the proof bytes, so backends
     * that parse snarkjs JSON can read it directly.</p>
     *
     * @param proofJson the raw proof.json content
     * @param vkJson    the raw verification_key.json content
     * @param publicJson the raw public.json content
     * @param circuitId the circuit identifier
     * @return a fully populated proof envelope
     */
    public static ZkProofEnvelope toEnvelopeFromJson(String proofJson, String vkJson,
                                                      String publicJson, CircuitId circuitId) {
        var proof = parseProof(proofJson);
        var inputs = parsePublicInputs(publicJson);

        ProofSystemId proofSystem = ProofSystemId.fromValue(proof.protocol());
        CurveId curve = CurveId.fromValue(proof.curve());

        byte[] vkBytes = vkJson.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] vkHash = sha256(vkBytes);

        return ZkProofEnvelope.builder()
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .proofBytes(proofJson.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                .publicInputs(inputs)
                .vkRef(new VerificationKeyRef.ByHash(vkHash))
                .proofFormat("snarkjs-json")
                .build();
    }

    // --- Serialization helpers ---

    /**
     * Serialize a snarkjs proof to its canonical JSON bytes (UTF-8, deterministic field order).
     */
    static byte[] serializeProofToBytes(SnarkjsProof proof) {
        try {
            return MAPPER.writeValueAsBytes(proof);
        } catch (Exception e) {
            throw new CodecException("Failed to serialize proof", e);
        }
    }

    /**
     * Serialize a snarkjs verification key to its canonical JSON bytes.
     */
    static byte[] serializeVkToBytes(SnarkjsVerificationKey vk) {
        try {
            return MAPPER.writeValueAsBytes(vk);
        } catch (Exception e) {
            throw new CodecException("Failed to serialize verification key", e);
        }
    }

    // --- Internal parsing helpers ---

    private static List<BigInteger> parseG1Point(JsonNode node) {
        if (!node.isArray()) {
            throw new CodecException("G1 point must be a JSON array");
        }
        List<BigInteger> coords = new ArrayList<>();
        for (JsonNode element : node) {
            coords.add(new BigInteger(element.asText()));
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG2Point(JsonNode node) {
        if (!node.isArray()) {
            throw new CodecException("G2 point must be a JSON array");
        }
        List<List<BigInteger>> coords = new ArrayList<>();
        for (JsonNode element : node) {
            if (element.isArray()) {
                List<BigInteger> pair = new ArrayList<>();
                for (JsonNode e : element) {
                    pair.add(new BigInteger(e.asText()));
                }
                coords.add(pair);
            } else {
                // Some formats use flat representation
                throw new CodecException("G2 point elements must be arrays (Fp2 coordinates)");
            }
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG1PointArray(JsonNode node) {
        if (!node.isArray()) {
            throw new CodecException("G1 point array must be a JSON array");
        }
        List<List<BigInteger>> points = new ArrayList<>();
        for (JsonNode element : node) {
            points.add(parseG1Point(element));
        }
        return points;
    }

    private static List<List<List<BigInteger>>> parseGtElement(JsonNode node) {
        if (!node.isArray()) {
            throw new CodecException("GT element must be a JSON array");
        }
        List<List<List<BigInteger>>> result = new ArrayList<>();
        for (JsonNode outerArray : node) {
            List<List<BigInteger>> middle = new ArrayList<>();
            for (JsonNode middleArray : outerArray) {
                List<BigInteger> inner = new ArrayList<>();
                for (JsonNode element : middleArray) {
                    inner.add(new BigInteger(element.asText()));
                }
                middle.add(inner);
            }
            result.add(middle);
        }
        return result;
    }

    private static void requireField(JsonNode root, String fieldName, String context) {
        if (!root.has(fieldName) || root.get(fieldName).isNull()) {
            throw new CodecException("Missing required field '" + fieldName + "' in " + context + " JSON");
        }
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
