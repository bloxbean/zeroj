package org.zeroj.codec;

import org.zeroj.api.*;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.ByteArrayOutputStream;
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
import java.util.Objects;

/**
 * Codec for snarkjs JSON proof files (proof.json, verification_key.json, public.json).
 *
 * <p>Parses the snarkjs Groth16 JSON format into ZeroJ model types.</p>
 */
public final class SnarkjsJsonCodec {

    private static final int MAX_JSON_BYTES = 8 * 1024 * 1024;
    private static final int MAX_DECIMAL_CHARS = 160;
    private static final int MAX_TEXT_CHARS = 128;
    private static final int MAX_PUBLIC_INPUTS = 1 << 20;
    private static final int MAX_IC_POINTS = 1 << 20;

    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(96)
                    .maxNumberLength(MAX_DECIMAL_CHARS)
                    .maxStringLength(MAX_DECIMAL_CHARS)
                    .build())
            .build());

    private SnarkjsJsonCodec() {}

    // --- Proof parsing ---

    /**
     * Parse a snarkjs proof.json file.
     */
    public static SnarkjsProof parseProof(Path path) {
        try {
            return parseProof(readBounded(path, "proof file"));
        } catch (IOException e) {
            throw new CodecException("Failed to read proof file: " + path, e);
        }
    }

    /**
     * Parse a snarkjs proof.json from an input stream.
     */
    public static SnarkjsProof parseProof(InputStream in) {
        try {
            return parseProof(readBounded(in, "proof input stream"));
        } catch (IOException e) {
            throw new CodecException("Failed to read proof input stream", e);
        }
    }

    /**
     * Parse a snarkjs proof.json from a JSON string.
     */
    public static SnarkjsProof parseProof(String json) {
        try {
            requireJsonSize(json, "proof JSON");
            JsonNode root = MAPPER.readTree(json);
            requireField(root, "pi_a", "proof");
            requireField(root, "pi_b", "proof");
            requireField(root, "pi_c", "proof");
            requireField(root, "protocol", "proof");
            requireField(root, "curve", "proof");

            List<BigInteger> piA = parseG1Point(root.get("pi_a"), "pi_a");
            List<List<BigInteger>> piB = parseG2Point(root.get("pi_b"), "pi_b");
            List<BigInteger> piC = parseG1Point(root.get("pi_c"), "pi_c");
            String protocol = parseText(root, "protocol");
            String curve = parseText(root, "curve");

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
            return parseVerificationKey(readBounded(path, "verification key file"));
        } catch (IOException e) {
            throw new CodecException("Failed to read verification key file: " + path, e);
        }
    }

    /**
     * Parse a snarkjs verification_key.json from an input stream.
     */
    public static SnarkjsVerificationKey parseVerificationKey(InputStream in) {
        try {
            return parseVerificationKey(readBounded(in, "verification key input stream"));
        } catch (IOException e) {
            throw new CodecException("Failed to read verification key input stream", e);
        }
    }

    /**
     * Parse a snarkjs verification_key.json from a JSON string.
     */
    public static SnarkjsVerificationKey parseVerificationKey(String json) {
        try {
            requireJsonSize(json, "verification key JSON");
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

            String protocol = parseText(root, "protocol");
            String curve = parseText(root, "curve");
            int nPublic = parseNonNegativeInt(root, "nPublic");

            List<BigInteger> vkAlpha1 = parseG1Point(root.get("vk_alpha_1"), "vk_alpha_1");
            List<List<BigInteger>> vkBeta2 = parseG2Point(root.get("vk_beta_2"), "vk_beta_2");
            List<List<BigInteger>> vkGamma2 = parseG2Point(root.get("vk_gamma_2"), "vk_gamma_2");
            List<List<BigInteger>> vkDelta2 = parseG2Point(root.get("vk_delta_2"), "vk_delta_2");
            List<List<List<BigInteger>>> vkAlphabeta12 = parseGtElement(root.get("vk_alphabeta_12"));
            List<List<BigInteger>> ic = parseG1PointArray(root.get("IC"));
            if (ic.size() != nPublic + 1) {
                throw new CodecException("verification_key IC length must be nPublic + 1");
            }

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
            return parsePublicInputs(readBounded(path, "public inputs file"));
        } catch (IOException e) {
            throw new CodecException("Failed to read public inputs file: " + path, e);
        }
    }

    /**
     * Parse a snarkjs public.json from an input stream.
     */
    public static PublicInputs parsePublicInputs(InputStream in) {
        try {
            return parsePublicInputs(readBounded(in, "public inputs input stream"));
        } catch (IOException e) {
            throw new CodecException("Failed to read public inputs input stream", e);
        }
    }

    /**
     * Parse a snarkjs public.json from a JSON string.
     */
    public static PublicInputs parsePublicInputs(String json) {
        try {
            requireJsonSize(json, "public inputs JSON");
            JsonNode root = MAPPER.readTree(json);
            if (!root.isArray()) {
                throw new CodecException("public.json must be a JSON array");
            }
            if (root.size() > MAX_PUBLIC_INPUTS) {
                throw new CodecException("public.json has too many public inputs");
            }
            List<BigInteger> values = new ArrayList<>();
            for (JsonNode element : root) {
                values.add(parseDecimal(element, "public input"));
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
     * <p>Serializes {@code proof} and {@code vk} into canonical snarkjs JSON ({@code pi_a},
     * {@code pi_b}, {@code pi_c}, {@code vk_alpha_1}, ..., {@code IC} with decimal string
     * coordinates) so the resulting envelope can be parsed and verified directly by ZeroJ
     * Groth16 verifiers. The envelope's {@link VerificationKeyRef.ByHash} hashes the canonical
     * bytes returned by {@link #toVerificationKeyBytes(SnarkjsVerificationKey)}. When you hold
     * raw {@code verification_key.json} bytes whose SHA-256 must match an existing registry entry,
     * use {@link #toEnvelopeFromJson(String, String, String, CircuitId)} instead.</p>
     *
     * @param proof     parsed snarkjs proof
     * @param vk        parsed snarkjs verification key
     * @param inputs    parsed public inputs
     * @param circuitId the circuit identifier
     * @return a fully populated proof envelope
     */
    public static ZkProofEnvelope toEnvelope(SnarkjsProof proof, SnarkjsVerificationKey vk,
                                              PublicInputs inputs, CircuitId circuitId) {
        Objects.requireNonNull(proof, "proof is required");
        Objects.requireNonNull(vk, "vk is required");
        Objects.requireNonNull(inputs, "inputs is required");
        Objects.requireNonNull(circuitId, "circuitId is required");
        ProofSystemId proofSystem = ProofSystemId.fromValue(proof.protocol());
        CurveId curve = CurveId.fromValue(proof.curve());
        validateProofVkInputs(proof, vk, inputs);

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
        Objects.requireNonNull(circuitId, "circuitId is required");
        var proof = parseProof(proofJson);
        var vk = parseVerificationKey(vkJson);
        var inputs = parsePublicInputs(publicJson);
        validateProofVkInputs(proof, vk, inputs);

        ProofSystemId proofSystem = ProofSystemId.fromValue(proof.protocol());
        CurveId curve = CurveId.fromValue(proof.curve());

        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkHash = sha256(vkBytes);

        return ZkProofEnvelope.builder()
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .publicInputs(inputs)
                .vkRef(new VerificationKeyRef.ByHash(vkHash))
                .proofFormat("snarkjs-json")
                .build();
    }

    /**
     * Serialize a parsed {@link SnarkjsVerificationKey} to canonical snarkjs JSON UTF-8 bytes
     * matching the {@link VerificationKeyRef.ByHash} produced by
     * {@link #toEnvelope(SnarkjsProof, SnarkjsVerificationKey, PublicInputs, CircuitId)}.
     */
    public static byte[] toVerificationKeyBytes(SnarkjsVerificationKey vk) {
        return serializeVkToBytes(vk);
    }

    // --- Serialization helpers ---

    /**
     * Serialize a snarkjs proof to canonical snarkjs JSON bytes (UTF-8, deterministic field order,
     * decimal string coordinates).
     */
    static byte[] serializeProofToBytes(SnarkjsProof proof) {
        Objects.requireNonNull(proof, "proof is required");
        try {
            ObjectNode root = MAPPER.createObjectNode();
            root.set("pi_a", encodeG1Point(proof.piA(), "pi_a"));
            root.set("pi_b", encodeG2Point(proof.piB(), "pi_b"));
            root.set("pi_c", encodeG1Point(proof.piC(), "pi_c"));
            root.put("protocol", requireValidText(proof.protocol(), "protocol"));
            root.put("curve", requireValidText(proof.curve(), "curve"));
            return MAPPER.writeValueAsBytes(root);
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to serialize proof", e);
        }
    }

    /**
     * Serialize a snarkjs verification key to canonical snarkjs JSON bytes (UTF-8, deterministic
     * field order, decimal string coordinates).
     */
    static byte[] serializeVkToBytes(SnarkjsVerificationKey vk) {
        Objects.requireNonNull(vk, "vk is required");
        try {
            if (vk.nPublic() < 0 || vk.nPublic() > MAX_PUBLIC_INPUTS) {
                throw new CodecException("Invalid verification_key nPublic: " + vk.nPublic());
            }
            if (vk.ic() == null || vk.ic().size() != vk.nPublic() + 1) {
                throw new CodecException("verification_key IC length must be nPublic + 1");
            }
            ObjectNode root = MAPPER.createObjectNode();
            root.put("protocol", requireValidText(vk.protocol(), "protocol"));
            root.put("curve", requireValidText(vk.curve(), "curve"));
            root.put("nPublic", vk.nPublic());
            root.set("vk_alpha_1", encodeG1Point(vk.vkAlpha1(), "vk_alpha_1"));
            root.set("vk_beta_2", encodeG2Point(vk.vkBeta2(), "vk_beta_2"));
            root.set("vk_gamma_2", encodeG2Point(vk.vkGamma2(), "vk_gamma_2"));
            root.set("vk_delta_2", encodeG2Point(vk.vkDelta2(), "vk_delta_2"));
            root.set("vk_alphabeta_12", encodeGtElement(vk.vkAlphabeta12(), "vk_alphabeta_12"));
            root.set("IC", encodeG1PointArray(vk.ic(), "IC"));
            return MAPPER.writeValueAsBytes(root);
        } catch (CodecException e) {
            throw e;
        } catch (Exception e) {
            throw new CodecException("Failed to serialize verification key", e);
        }
    }

    private static ArrayNode encodeG1Point(List<BigInteger> point, String fieldName) {
        if (point == null || point.size() != 3) {
            throw new CodecException("G1 point must have 3 coordinates: " + fieldName);
        }
        ArrayNode arr = MAPPER.createArrayNode();
        for (BigInteger coord : point) {
            arr.add(encodeDecimal(coord, fieldName));
        }
        return arr;
    }

    private static ArrayNode encodeG2Point(List<List<BigInteger>> point, String fieldName) {
        if (point == null || point.size() != 3) {
            throw new CodecException("G2 point must have 3 Fp2 coordinates: " + fieldName);
        }
        ArrayNode arr = MAPPER.createArrayNode();
        for (List<BigInteger> pair : point) {
            if (pair == null || pair.size() != 2) {
                throw new CodecException("G2 coordinate must be a 2-element Fp2 array: " + fieldName);
            }
            ArrayNode pairNode = MAPPER.createArrayNode();
            pairNode.add(encodeDecimal(pair.get(0), fieldName));
            pairNode.add(encodeDecimal(pair.get(1), fieldName));
            arr.add(pairNode);
        }
        return arr;
    }

    private static ArrayNode encodeGtElement(List<List<List<BigInteger>>> gt, String fieldName) {
        if (gt == null || gt.size() != 2) {
            throw new CodecException("GT element must have 2 outer Fp6 entries: " + fieldName);
        }
        ArrayNode outer = MAPPER.createArrayNode();
        for (List<List<BigInteger>> mid : gt) {
            if (mid == null || mid.size() != 3) {
                throw new CodecException("GT Fp6 entry must have 3 Fp2 entries: " + fieldName);
            }
            ArrayNode midNode = MAPPER.createArrayNode();
            for (List<BigInteger> pair : mid) {
                if (pair == null || pair.size() != 2) {
                    throw new CodecException("GT Fp2 entry must have 2 Fp elements: " + fieldName);
                }
                ArrayNode pairNode = MAPPER.createArrayNode();
                pairNode.add(encodeDecimal(pair.get(0), fieldName));
                pairNode.add(encodeDecimal(pair.get(1), fieldName));
                midNode.add(pairNode);
            }
            outer.add(midNode);
        }
        return outer;
    }

    private static ArrayNode encodeG1PointArray(List<List<BigInteger>> points, String fieldName) {
        if (points == null || points.isEmpty() || points.size() > MAX_IC_POINTS) {
            throw new CodecException("Invalid G1 point array size: " + fieldName);
        }
        ArrayNode arr = MAPPER.createArrayNode();
        for (int i = 0; i < points.size(); i++) {
            arr.add(encodeG1Point(points.get(i), fieldName + "[" + i + "]"));
        }
        return arr;
    }

    private static String encodeDecimal(BigInteger value, String fieldName) {
        if (value == null || value.signum() < 0) {
            throw new CodecException("Coordinate must be a non-negative integer: " + fieldName);
        }
        String text = value.toString();
        if (text.length() > MAX_DECIMAL_CHARS) {
            throw new CodecException("Coordinate exceeds maximum decimal length: " + fieldName);
        }
        return text;
    }

    private static String requireValidText(String value, String fieldName) {
        if (value == null || value.isBlank() || value.length() > MAX_TEXT_CHARS) {
            throw new CodecException("Invalid text field: " + fieldName);
        }
        return value;
    }

    // --- Internal parsing helpers ---

    private static List<BigInteger> parseG1Point(JsonNode node, String fieldName) {
        if (node == null || !node.isArray() || node.size() != 3) {
            throw new CodecException("G1 point must be a 3-element JSON array: " + fieldName);
        }
        List<BigInteger> coords = new ArrayList<>();
        for (JsonNode element : node) {
            coords.add(parseDecimal(element, fieldName));
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG2Point(JsonNode node, String fieldName) {
        if (node == null || !node.isArray() || node.size() != 3) {
            throw new CodecException("G2 point must be a 3-element JSON array: " + fieldName);
        }
        List<List<BigInteger>> coords = new ArrayList<>();
        for (JsonNode element : node) {
            if (!element.isArray() || element.size() != 2) {
                throw new CodecException("G2 point elements must be 2-element Fp2 arrays: " + fieldName);
            }
            List<BigInteger> pair = new ArrayList<>();
            for (JsonNode e : element) {
                pair.add(parseDecimal(e, fieldName));
            }
            coords.add(pair);
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG1PointArray(JsonNode node) {
        if (!node.isArray()) {
            throw new CodecException("G1 point array must be a JSON array");
        }
        if (node.size() > MAX_IC_POINTS) {
            throw new CodecException("G1 point array is too large");
        }
        List<List<BigInteger>> points = new ArrayList<>();
        for (JsonNode element : node) {
            points.add(parseG1Point(element, "IC"));
        }
        return points;
    }

    private static List<List<List<BigInteger>>> parseGtElement(JsonNode node) {
        if (!node.isArray() || node.size() != 2) {
            throw new CodecException("GT element must be a 2-element JSON array");
        }
        List<List<List<BigInteger>>> result = new ArrayList<>();
        for (JsonNode outerArray : node) {
            if (!outerArray.isArray() || outerArray.size() != 3) {
                throw new CodecException("GT element middle array must have 3 elements");
            }
            List<List<BigInteger>> middle = new ArrayList<>();
            for (JsonNode middleArray : outerArray) {
                if (!middleArray.isArray() || middleArray.size() != 2) {
                    throw new CodecException("GT element inner array must have 2 elements");
                }
                List<BigInteger> inner = new ArrayList<>();
                for (JsonNode element : middleArray) {
                    inner.add(parseDecimal(element, "vk_alphabeta_12"));
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

    private static String parseText(JsonNode root, String fieldName) {
        JsonNode node = root.get(fieldName);
        if (node == null || !node.isTextual() || node.asText().isBlank()
                || node.asText().length() > MAX_TEXT_CHARS) {
            throw new CodecException("Missing or invalid text field: " + fieldName);
        }
        return node.asText();
    }

    private static int parseNonNegativeInt(JsonNode root, String fieldName) {
        JsonNode node = root.get(fieldName);
        BigInteger value = parseDecimal(node, fieldName);
        if (value.bitLength() > 31) {
            throw new CodecException("Integer field too large: " + fieldName);
        }
        return value.intValueExact();
    }

    private static BigInteger parseDecimal(JsonNode node, String fieldName) {
        if (node == null || !(node.isTextual() || node.isIntegralNumber())) {
            throw new CodecException("Missing or invalid decimal field: " + fieldName);
        }
        String text = node.asText();
        if (text.length() > MAX_DECIMAL_CHARS || !isCanonicalDecimal(text)) {
            throw new CodecException("Invalid decimal field: " + fieldName);
        }
        return new BigInteger(text);
    }

    private static boolean isCanonicalDecimal(String text) {
        if (text.isEmpty()) return false;
        if (text.length() > 1 && text.charAt(0) == '0') return false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static void validateProofVkInputs(SnarkjsProof proof, SnarkjsVerificationKey vk, PublicInputs inputs) {
        if (!proof.protocol().equals(vk.protocol())) {
            throw new CodecException("proof and verification key protocols do not match");
        }
        if (!proof.curve().equals(vk.curve())) {
            throw new CodecException("proof and verification key curves do not match");
        }
        if (vk.nPublic() != inputs.size()) {
            throw new CodecException("public input count does not match verification key nPublic");
        }
    }

    private static void requireJsonSize(String json, String label) {
        if (json == null || json.getBytes(StandardCharsets.UTF_8).length > MAX_JSON_BYTES) {
            throw new CodecException(label + " is too large");
        }
    }

    private static String readBounded(Path path, String label) throws IOException {
        if (Files.size(path) > MAX_JSON_BYTES) {
            throw new IOException(label + " exceeds supported size limit");
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static String readBounded(InputStream in, String label) throws IOException {
        if (in == null) {
            throw new IOException(label + " must not be null");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > MAX_JSON_BYTES) {
                throw new IOException(label + " exceeds supported size limit");
            }
            out.write(buffer, 0, read);
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
