package com.bloxbean.cardano.zeroj.codec;

import com.bloxbean.cardano.zeroj.api.*;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
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

    private static final int MAX_JSON_BYTES = 2 * 1024 * 1024;
    private static final int MAX_DECIMAL_CHARS = 160;
    private static final int MAX_TEXT_CHARS = 128;
    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxNestingDepth(64)
                    .maxNumberLength(MAX_DECIMAL_CHARS)
                    .maxStringLength(MAX_DECIMAL_CHARS)
                    .build())
            .build());

    private SnarkjsPlonkCodec() {}

    // --- Proof parsing ---

    public static SnarkjsPlonkProof parseProof(Path path) {
        try {
            return parseProof(readBounded(path, "PlonK proof file"));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK proof file: " + path, e);
        }
    }

    public static SnarkjsPlonkProof parseProof(InputStream in) {
        try {
            return parseProof(readBounded(in, "PlonK proof input stream"));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK proof input stream", e);
        }
    }

    public static SnarkjsPlonkProof parseProof(String json) {
        try {
            requireJsonSize(json, "PlonK proof JSON");
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
                    parseText(root, "protocol"),
                    parseText(root, "curve")
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
            return parseVerificationKey(readBounded(path, "PlonK VK file"));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK VK file: " + path, e);
        }
    }

    public static SnarkjsPlonkVerificationKey parseVerificationKey(InputStream in) {
        try {
            return parseVerificationKey(readBounded(in, "PlonK VK input stream"));
        } catch (IOException e) {
            throw new CodecException("Failed to read PlonK VK input stream", e);
        }
    }

    public static SnarkjsPlonkVerificationKey parseVerificationKey(String json) {
        try {
            requireJsonSize(json, "PlonK verification key JSON");
            JsonNode root = MAPPER.readTree(json);

            return new SnarkjsPlonkVerificationKey(
                    parseText(root, "protocol"),
                    parseText(root, "curve"),
                    parseNonNegativeInt(root, "nPublic"),
                    parseNonNegativeInt(root, "power"),
                    parseScalar(root, "k1"),
                    parseScalar(root, "k2"),
                    parseG1(root, "Qm"),
                    parseG1(root, "Ql"),
                    parseG1(root, "Qr"),
                    parseG1(root, "Qo"),
                    parseG1(root, "Qc"),
                    parseG1(root, "S1"),
                    parseG1(root, "S2"),
                    parseG1(root, "S3"),
                    parseG2(root, "X_2"),
                    parseScalar(root, "w")
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
        if (node == null || !node.isArray() || node.size() != 3) {
            throw new CodecException("Missing or invalid G1 field: " + fieldName);
        }
        List<BigInteger> coords = new ArrayList<>();
        for (var element : node) {
            coords.add(parseDecimal(element, fieldName));
        }
        return coords;
    }

    private static List<List<BigInteger>> parseG2(JsonNode root, String fieldName) {
        var node = root.get(fieldName);
        if (node == null || !node.isArray() || node.size() != 3) {
            throw new CodecException("Missing or invalid G2 field: " + fieldName);
        }
        List<List<BigInteger>> coords = new ArrayList<>();
        for (var element : node) {
            if (!element.isArray() || element.size() != 2) {
                throw new CodecException("Invalid G2 field: " + fieldName);
            }
            List<BigInteger> pair = new ArrayList<>();
            for (var e : element) {
                pair.add(parseDecimal(e, fieldName));
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
        return parseDecimal(node, fieldName);
    }

    private static String parseText(JsonNode root, String fieldName) {
        var node = root.get(fieldName);
        if (node == null || !node.isTextual() || node.asText().isBlank()
                || node.asText().length() > MAX_TEXT_CHARS) {
            throw new CodecException("Missing or invalid text field: " + fieldName);
        }
        return node.asText();
    }

    private static int parseNonNegativeInt(JsonNode root, String fieldName) {
        var node = root.get(fieldName);
        if (node == null) {
            throw new CodecException("Missing integer field: " + fieldName);
        }
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

    private static void requireJsonSize(String json, String label) {
        if (json == null || json.getBytes(StandardCharsets.UTF_8).length > MAX_JSON_BYTES) {
            throw new CodecException(label + " is too large");
        }
    }

    private static String readBounded(Path path, String label) throws IOException {
        if (Files.size(path) > MAX_JSON_BYTES) {
            throw new CodecException(label + " is too large");
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static String readBounded(InputStream in, String label) throws IOException {
        if (in == null) {
            throw new CodecException(label + " is null");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > MAX_JSON_BYTES) {
                throw new CodecException(label + " is too large");
            }
            out.write(buffer, 0, read);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }
}
