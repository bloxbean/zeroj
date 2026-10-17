package org.zeroj.circuit.lib.jubjub;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentEnvelope;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0059 M2: runs every case of the {@code zeroj-commitment-vectors-v1} files
 * ({@code commitment-profiles-v1} §13) through the strict Java APIs.
 *
 * <p>The files are written by {@code commitment-vectors-reference/emit_commitment_vectors_v1.py}, an
 * independent Python implementation of the spec; nothing here derives an expected value from the
 * code under test. Before any case runs, the whole file is validated against §13 (required and
 * allowed fields at every level, value shapes and domains, relation operators and arity, the
 * streams rule); an invalid fixture rejects the file. Each positive case must then produce exactly
 * its expected value (compared as JSON, ignoring object key order); each negative case must fail
 * with exactly its error class ({@code OPENING_MISMATCH} is a {@code false} verification). A
 * self-test confirms the runner notices mutated expectations and invalid fixtures.
 */
class CommitmentProfileVectorsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();
    private static final String DIR = "/test-vectors/commitment-profiles-v1/";
    private static final List<String> PROFILES =
            List.of("pedersen-jubjub-v1", "pedersen-jubjub-vector-v1", "pedersen-jubjub-bytes-v1");
    private static final Pattern HEX_STRING = Pattern.compile("([0-9a-f]{2})*");
    private static final Pattern INTEGER = Pattern.compile("-?(0|[1-9][0-9]*)");

    /** One operation of one profile: required and optional input fields, expected fields (§13.3 table). */
    private record Op(Set<String> required, Set<String> optional, Set<String> expected) {
    }

    private static Op op(Set<String> required, Set<String> optional, Set<String> expected) {
        return new Op(required, optional, expected);
    }

    private static final Set<String> POINT = Set.of("pointHex");
    private static final Set<String> UV = Set.of("uHex", "vHex");
    private static final Set<String> NONE = Set.of();

    private static final Map<String, Map<String, Op>> OPS = Map.of(
            "pedersen-jubjub-v1", Map.of(
                    "decodePoint", op(POINT, NONE, UV),
                    "commit", op(Set.of("value", "blinding"), NONE, POINT),
                    "commitLegacy", op(Set.of("value", "blinding"), NONE, POINT),
                    "verifyOpening", op(Set.of("pointHex", "value", "blinding"), Set.of("amountBits"), Set.of("result")),
                    "encodeOpening", op(Set.of("value", "blinding"), NONE, Set.of("openingHex")),
                    "decodeOpening", op(Set.of("openingHex"), NONE, Set.of("value", "blinding")),
                    "encodeEnvelope", op(POINT, NONE, Set.of("envelopeHex")),
                    "decodeEnvelope", op(Set.of("envelopeHex", "expectedProfileId"), NONE, POINT),
                    "relation", op(Set.of("op", "pointsHex"), NONE, POINT)),
            "pedersen-jubjub-bytes-v1", Map.of(
                    "decodePoint", op(POINT, NONE, UV),
                    "commit", op(Set.of("payload", "blinding"), Set.of("declaredLength", "maxBytes"), POINT),
                    "hashToScalar", op(Set.of("payload"), NONE,
                            Set.of("b0Hex", "b1Hex", "b2Hex", "uniformBytesHex", "scalar")),
                    "verifyOpening", op(Set.of("pointHex", "payload", "blinding"), NONE, Set.of("result")),
                    "encodeOpening", op(Set.of("blinding"), NONE, Set.of("openingHex")),
                    "decodeOpening", op(Set.of("openingHex"), NONE, Set.of("blinding")),
                    "encodeEnvelope", op(POINT, NONE, Set.of("envelopeHex")),
                    "decodeEnvelope", op(Set.of("envelopeHex", "expectedProfileId"), NONE, POINT)),
            "pedersen-jubjub-vector-v1", Map.of(
                    "decodePoint", op(Set.of("pointHex", "schema"), NONE, UV),
                    "commit", op(Set.of("schema", "values", "blinding"), NONE, POINT),
                    "verifyOpening", op(Set.of("pointHex", "schema", "policy", "values", "blinding"),
                            Set.of("policySchema"), Set.of("result")),
                    "encodeOpening", op(Set.of("schema", "policy", "values", "blinding"), NONE, Set.of("openingHex")),
                    "decodeOpening", op(Set.of("openingHex", "schema", "policy"), NONE,
                            Set.of("schema", "policy", "values", "blinding")),
                    "encodeEnvelope", op(Set.of("pointHex", "schema"), NONE, Set.of("envelopeHex")),
                    "decodeEnvelope", op(Set.of("envelopeHex", "expectedProfileId", "schema"), NONE, POINT),
                    "relation", op(Set.of("op", "pointsHex", "schema"), NONE, POINT),
                    "configurePolicy", op(Set.of("schema", "policy"), NONE, Set.of("result"))));

    @ParameterizedTest
    @ValueSource(strings = {"pedersen-jubjub-v1", "pedersen-jubjub-vector-v1", "pedersen-jubjub-bytes-v1"})
    @DisplayName("Every positive and negative case of the independent vector file holds against the strict Java APIs")
    void vectors(String profileId) throws IOException {
        JsonNode file = load(profileId);
        assertEquals(profileId, file.path("profileId").asText());
        List<String> failures = run(file);
        assertEquals(List.of(), failures, profileId + ": " + failures.size() + " failing cases");
        assertTrue(file.get("positive").size() >= 20, "positive cases");
        assertTrue(file.get("negative").size() >= 50, "negative cases");
    }

    @Test
    @DisplayName("Every file covers every operation of its kind and every error class the kind can produce")
    void coverage() throws IOException {
        Map<String, Set<String>> errors = Map.of(
                "pedersen-jubjub-v1", Set.of("MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR",
                        "OUT_OF_RANGE", "PROFILE_MISMATCH", "INVALID_CONFIGURATION", "OPENING_MISMATCH"),
                "pedersen-jubjub-bytes-v1", Set.of("MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR",
                        "LENGTH_OUT_OF_RANGE", "PROFILE_MISMATCH", "OPENING_MISMATCH"),
                "pedersen-jubjub-vector-v1", Set.of("MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR",
                        "OUT_OF_RANGE", "PROFILE_MISMATCH", "INVALID_CONFIGURATION", "OPENING_MISMATCH"));
        for (String profileId : PROFILES) {
            JsonNode file = load(profileId);
            Set<String> operations = new TreeSet<>();
            Set<String> classes = new TreeSet<>();
            for (JsonNode c : file.get("positive")) operations.add(c.get("operation").asText());
            for (JsonNode c : file.get("negative")) classes.add(c.get("error").asText());
            assertEquals(new TreeSet<>(OPS.get(profileId).keySet()), operations, profileId + " positive operations");
            assertEquals(new TreeSet<>(errors.get(profileId)), classes, profileId + " error classes");
        }
    }

    @Test
    @DisplayName("Self-test: the runner reports a changed expected point, a changed error class and a wrong verdict")
    void runnerDetectsMutations() throws IOException {
        for (String profileId : PROFILES) {
            JsonNode original = load(profileId);
            assertEquals(List.of(), run(original));

            ObjectNode positive = original.deepCopy();
            for (JsonNode c : positive.get("positive")) {
                JsonNode expected = c.get("expected");
                if (expected.has("pointHex")) {
                    String hex = expected.get("pointHex").asText();
                    ((ObjectNode) expected).put("pointHex", (hex.charAt(0) == '0' ? '1' : '0') + hex.substring(1));
                    break;
                }
            }
            assertFalse(run(positive).isEmpty(), profileId + ": a changed expected point went unnoticed");

            ObjectNode negative = original.deepCopy();
            for (JsonNode c : negative.get("negative")) {
                if (c.get("error").asText().equals("NON_CANONICAL_SCALAR")) {
                    ((ObjectNode) c).put("error", "OUT_OF_RANGE");
                    break;
                }
            }
            assertFalse(run(negative).isEmpty(), profileId + ": a changed error class went unnoticed");

            ObjectNode verdict = original.deepCopy();
            ArrayNode negatives = (ArrayNode) verdict.get("negative");
            for (int i = 0; i < negatives.size(); i++) {
                ObjectNode c = (ObjectNode) negatives.get(i);
                if (c.get("error").asText().equals("OPENING_MISMATCH")) {
                    c.remove("error");
                    c.set("expected", JSON.createObjectNode().put("result", "true"));
                    ((ArrayNode) verdict.get("positive")).add(negatives.remove(i));
                    break;
                }
            }
            assertFalse(run(verdict).isEmpty(), profileId + ": a false verdict reported as true went unnoticed");
        }
    }

    @Test
    @DisplayName("Reordering object keys in a valid file changes nothing (JSON object members are unordered)")
    void keyOrderIsIrrelevant() throws IOException {
        for (String profileId : PROFILES) {
            JsonNode reordered = reverseKeys(load(profileId));
            assertEquals(List.of(), run(reordered), profileId);
        }
    }

    @Test
    @DisplayName("Fixture validation rejects the whole file for every malformed fixture shape")
    void fixtureValidation() throws IOException {
        // A JSON number anywhere.
        assertInvalid("pedersen-jubjub-v1", "decode-point-identity", c -> ((ObjectNode) c.get("input")).put("pointHex", 1));
        // Wrong relation arity, and an unknown relation operator that a point failure would otherwise mask.
        assertInvalid("pedersen-jubjub-v1", "relation-negate", c -> ((ArrayNode) c.get("input").get("pointsHex")).add("00"));
        assertInvalid("pedersen-jubjub-v1", "relation-order-first-point-first",
                c -> ((ObjectNode) c.get("input")).put("op", "bogus"));
        assertInvalid("pedersen-jubjub-vector-v1", null, file -> {
            for (JsonNode c : file.get("positive")) {
                if (c.get("operation").asText().equals("relation")) {
                    ((ObjectNode) c.get("input")).put("op", "negate");
                    return;
                }
            }
        });
        // A missing required field: configurePolicy without its policy would otherwise pass vacuously.
        assertInvalid("pedersen-jubjub-vector-v1", "configure-policy-widened-2", c -> ((ObjectNode) c.get("input")).remove("policy"));
        // Unknown nested fields in policy, schema and payload; an unknown top-level case field.
        assertInvalid("pedersen-jubjub-vector-v1", "configure-policy-widened-2",
                c -> ((ObjectNode) c.get("input").get("policy")).put("extra", "1"));
        assertInvalid("pedersen-jubjub-vector-v1", "configure-policy-widened-2",
                c -> ((ObjectNode) c.get("input").get("schema")).put("extra", "1"));
        assertInvalid("pedersen-jubjub-bytes-v1", "commit-blinding-q", c -> ((ObjectNode) c.get("input").get("payload")).put("extra", "1"));
        assertInvalid("pedersen-jubjub-bytes-v1", "commit-blinding-q", c -> ((ObjectNode) c).put("note", "x"));
        // The streams rule: an out-of-range length in a case whose class is not LENGTH_OUT_OF_RANGE.
        assertInvalid("pedersen-jubjub-bytes-v1", "commit-blinding-q",
                c -> ((ObjectNode) c.get("input")).put("declaredLength", "-1"));
        // A declared length that disagrees with the payload in a positive case.
        assertInvalid("pedersen-jubjub-bytes-v1", "commit-hello-12345-declared-length",
                c -> ((ObjectNode) c.get("input")).put("declaredLength", "17"));
        // An expected-profile identifier that is not the file's own.
        assertInvalid("pedersen-jubjub-v1", null, file -> {
            for (JsonNode c : file.get("positive")) {
                if (c.get("operation").asText().equals("decodeEnvelope")) {
                    ((ObjectNode) c.get("input")).put("expectedProfileId", "pedersen-jubjub-bytes-v1");
                    return;
                }
            }
        });
        // Legacy vector commit with a non-canonical blinding (it would be reduced and still match),
        // an over-width value, and an invalid schema (width 0).
        assertInvalid("pedersen-jubjub-vector-v1", "commit-zero-zero",
                c -> ((ObjectNode) c.get("input")).put("blinding", JubjubCurve.SUBGROUP_ORDER.toString()));
        assertInvalid("pedersen-jubjub-vector-v1", "commit-zero-zero",
                c -> ((ArrayNode) c.get("input").get("values")).set(1, JSON.getNodeFactory().textNode("4294967296")));
        assertInvalid("pedersen-jubjub-vector-v1", "configure-policy-widened-2",
                c -> ((ObjectNode) c.get("input").get("schema").get("entries").get(0)).put("width", "0"));
        assertInvalid("pedersen-jubjub-vector-v1", "decode-opening-dim16-schema-widths",
                c -> ((ObjectNode) c.get("expected").get("schema").get("entries").get(0)).put("width", "0"));
        // A missing expected field, and a non-lowercase hex string.
        assertInvalid("pedersen-jubjub-v1", "decode-point-identity", c -> ((ObjectNode) c.get("expected")).remove("vHex"));
        assertInvalid("pedersen-jubjub-v1", "decode-point-identity",
                c -> ((ObjectNode) c.get("input")).put("pointHex", "01000000000000000000000000000000000000000000000000000000000000AA"));
    }

    // ---- validation (spec §13.1–§13.3) ----

    private static void validate(JsonNode file) {
        requireObject(file, "$", Set.of("schema", "profileId", "spec", "generator", "positive", "negative"), NONE);
        if (!"zeroj-commitment-vectors-v1".equals(file.get("schema").asText())) invalid("$.schema");
        String profileId = file.get("profileId").asText();
        Map<String, Op> ops = OPS.get(profileId);
        if (ops == null) invalid("unknown profile " + profileId);
        if (!file.get("spec").isArray() || file.get("spec").isEmpty()) invalid("$.spec");
        for (JsonNode s : file.get("spec")) {
            requireObject(s, "$.spec[]", Set.of("path", "date", "sha256"), Set.of("revision"));
        }
        requireObject(file.get("generator"), "$.generator", Set.of("script", "scriptSha256", "python"), NONE);
        if (!file.get("generator").get("script").asText().endsWith("emit_commitment_vectors_v1.py")) invalid("$.generator.script");
        Set<String> names = new HashSet<>();
        for (String kind : List.of("positive", "negative")) {
            if (!file.get(kind).isArray()) invalid("$." + kind);
            for (JsonNode c : file.get(kind)) {
                String where = "$." + kind + "[" + c.path("name").asText() + "]";
                boolean positive = kind.equals("positive");
                requireObject(c, where, Set.of("name", "operation", "input", positive ? "expected" : "error"), NONE);
                if (!names.add(c.get("name").asText())) invalid(where + ": duplicate name");
                Op op = ops.get(c.get("operation").asText());
                if (op == null) invalid(where + ": unknown operation");
                JsonNode in = c.get("input");
                requireObject(in, where + ".input", op.required(), op.optional());
                for (Iterator<Map.Entry<String, JsonNode>> it = in.fields(); it.hasNext(); ) {
                    Map.Entry<String, JsonNode> e = it.next();
                    validateField(profileId, e.getKey(), e.getValue(), where + ".input." + e.getKey());
                }
                validateRelation(profileId, c.get("operation").asText(), in, where);
                if (positive) {
                    requireObject(c.get("expected"), where + ".expected", op.expected(), NONE);
                    for (Iterator<Map.Entry<String, JsonNode>> it = c.get("expected").fields(); it.hasNext(); ) {
                        Map.Entry<String, JsonNode> e = it.next();
                        validateField(profileId, e.getKey(), e.getValue(), where + ".expected." + e.getKey());
                    }
                } else {
                    try {
                        CommitmentError.valueOf(c.get("error").asText());
                    } catch (IllegalArgumentException e) {
                        invalid(where + ": unknown error class");
                    }
                }
                if (profileId.equals("pedersen-jubjub-bytes-v1")) {
                    validateStreams(c, positive, where);
                }
                if (profileId.equals("pedersen-jubjub-vector-v1")) {
                    validateVectorCase(c.get("operation").asText(), in, where);
                }
            }
        }
    }

    private static void validateField(String profileId, String field, JsonNode v, String where) {
        switch (field) {
            case "pointHex", "envelopeHex", "openingHex", "uHex", "vHex", "b0Hex", "b1Hex", "b2Hex", "uniformBytesHex" ->
                    requireHex(v, where);
            case "value", "blinding", "scalar" -> requireInteger(v, where);
            case "amountBits" -> requireInt32(v, where);
            case "declaredLength", "maxBytes" -> requireInt64(v, where);
            case "values" -> {
                if (!v.isArray()) invalid(where);
                for (JsonNode x : v) requireInteger(x, where + "[]");
            }
            case "pointsHex" -> {
                if (!v.isArray()) invalid(where);
                for (JsonNode x : v) requireHex(x, where + "[]");
            }
            case "op" -> {
                Set<String> allowed = profileId.equals("pedersen-jubjub-v1")
                        ? Set.of("add", "subtract", "negate") : Set.of("add", "subtract");
                if (!v.isTextual() || !allowed.contains(v.asText())) invalid(where + ": relation operator");
            }
            case "expectedProfileId" -> {
                if (!v.isTextual() || !v.asText().equals(profileId)) invalid(where + ": not the file's profile");
            }
            case "result" -> {
                if (!v.isTextual() || !Set.of("true", "ok").contains(v.asText())) invalid(where);
            }
            case "payload" -> {
                if (v.has("hex")) {
                    requireObject(v, where, Set.of("hex"), NONE);
                    requireHex(v.get("hex"), where + ".hex");
                } else {
                    requireObject(v, where, Set.of("pattern", "length"), NONE);
                    if (!"131i+17".equals(v.get("pattern").asText())) invalid(where + ".pattern");
                    requireInt32(v.get("length"), where + ".length");
                    if (Integer.parseInt(v.get("length").asText()) < 0) invalid(where + ".length");
                }
            }
            case "schema", "policySchema" -> {
                requireObject(v, where, Set.of("id", "version", "entries"), NONE);
                if (!v.get("id").isTextual()) invalid(where + ".id");
                requireInt32(v.get("version"), where + ".version");
                if (!v.get("entries").isArray() || v.get("entries").isEmpty()) invalid(where + ".entries");
                for (JsonNode e : v.get("entries")) {
                    requireObject(e, where + ".entries[]", Set.of("label", "width"), NONE);
                    if (!e.get("label").isTextual()) invalid(where + ".entries[].label");
                    requireInt32(e.get("width"), where + ".entries[].width");
                }
                // §13.2: every schema in a file (input or expected) is valid.
                try {
                    schema(v);
                } catch (IllegalArgumentException e) {
                    invalid(where + ": not a valid schema (" + e.getMessage() + ")");
                }
            }
            case "policy" -> {
                String kind = v.path("kind").asText();
                if (kind.equals("widened")) {
                    requireObject(v, where, Set.of("kind", "addedTerms"), NONE);
                    requireInt32(v.get("addedTerms"), where + ".addedTerms");
                } else if (kind.equals("schema-widths") || kind.equals("residue-only")) {
                    requireObject(v, where, Set.of("kind"), NONE);
                } else {
                    invalid(where + ".kind");
                }
            }
            default -> invalid(where + ": unknown field");
        }
    }

    /**
     * §13.3: the legacy vector {@code commit} is used with canonical, width-respecting inputs only.
     */
    private static void validateVectorCase(String operation, JsonNode in, String where) {
        // Schemas were already validated with the other fields.
        if (!operation.equals("commit")) return;
        PedersenVectorSchema schema = schema(in.get("schema"));
        List<BigInteger> values = integers(in, "values");
        if (values.size() != schema.dimension()) invalid(where + ": commit values do not match the schema dimension");
        for (int i = 0; i < values.size(); i++) {
            BigInteger v = values.get(i);
            if (v.signum() < 0 || v.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0 || v.bitLength() > schema.width(i)) {
                invalid(where + ": commit value " + i + " is not canonical within its width");
            }
        }
        BigInteger r = integer(in, "blinding");
        if (r.signum() < 0 || r.compareTo(JubjubCurve.SUBGROUP_ORDER) >= 0) {
            invalid(where + ": commit blinding is not canonical");
        }
    }

    /** §13.2: {@code add}/{@code subtract} take exactly two points, {@code negate} exactly one. */
    private static void validateRelation(String profileId, String operation, JsonNode in, String where) {
        if (!operation.equals("relation")) return;
        int arity = in.get("op").asText().equals("negate") ? 1 : 2;
        if (in.get("pointsHex").size() != arity) invalid(where + ": relation arity");
    }

    /**
     * §13.3 streams rule: a length field only on {@code commit}, never both; outside
     * {@code LENGTH_OUT_OF_RANGE} cases {@code declaredLength} equals the payload length and
     * {@code maxBytes} is at least it; in those cases the payload is empty and the value is outside
     * {@code [0, MAX_PAYLOAD_BYTES]}.
     */
    private static void validateStreams(JsonNode c, boolean positive, String where) {
        JsonNode in = c.get("input");
        boolean declared = in.has("declaredLength");
        boolean max = in.has("maxBytes");
        if (!declared && !max) return;
        if (declared && max) invalid(where + ": declaredLength and maxBytes together");
        long bound = Long.parseLong(in.get(declared ? "declaredLength" : "maxBytes").asText());
        long length = payload(in.get("payload")).length;
        boolean lengthCase = !positive && c.get("error").asText().equals("LENGTH_OUT_OF_RANGE");
        if (lengthCase) {
            if (length != 0 || (bound >= 0 && bound <= PedersenBytesHash.MAX_PAYLOAD_BYTES)) {
                invalid(where + ": a LENGTH_OUT_OF_RANGE case needs an empty payload and an out-of-range bound");
            }
        } else if (declared ? bound != length : bound < length) {
            invalid(where + ": streams rule (declaredLength must equal, maxBytes must cover, the payload length)");
        }
    }

    private static void requireObject(JsonNode node, String where, Set<String> required, Set<String> optional) {
        if (node == null || !node.isObject()) invalid(where + ": not an object");
        for (String r : required) {
            if (!node.has(r)) invalid(where + ": missing " + r);
        }
        for (Iterator<String> it = node.fieldNames(); it.hasNext(); ) {
            String f = it.next();
            if (!required.contains(f) && !optional.contains(f)) invalid(where + ": unexpected field " + f);
        }
    }

    private static void requireHex(JsonNode v, String where) {
        if (v == null || !v.isTextual() || !HEX_STRING.matcher(v.asText()).matches()) invalid(where + ": not lowercase hex");
    }

    private static void requireInteger(JsonNode v, String where) {
        if (v == null || !v.isTextual() || !INTEGER.matcher(v.asText()).matches()) invalid(where + ": not a decimal integer");
    }

    private static void requireInt32(JsonNode v, String where) {
        requireInteger(v, where);
        try {
            Integer.parseInt(v.asText());
        } catch (NumberFormatException e) {
            invalid(where + ": outside the signed 32-bit domain");
        }
    }

    private static void requireInt64(JsonNode v, String where) {
        requireInteger(v, where);
        try {
            Long.parseLong(v.asText());
        } catch (NumberFormatException e) {
            invalid(where + ": outside the signed 64-bit domain");
        }
    }

    private static void requireNoNumbers(JsonNode node, String path) {
        if (node.isObject()) {
            for (Iterator<Map.Entry<String, JsonNode>> it = node.fields(); it.hasNext(); ) {
                Map.Entry<String, JsonNode> e = it.next();
                requireNoNumbers(e.getValue(), path + "." + e.getKey());
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) requireNoNumbers(node.get(i), path + "[" + i + "]");
        } else if (!node.isTextual()) {
            invalid("non-string scalar at " + path + " (spec §13.2)");
        }
    }

    private static void invalid(String message) {
        throw new IllegalStateException("invalid fixture: " + message);
    }

    // ---- runner ----

    private static List<String> run(JsonNode file) {
        requireNoNumbers(file, "$");
        validate(file);
        String profileId = file.get("profileId").asText();
        List<String> failures = new ArrayList<>();
        for (JsonNode c : file.get("positive")) {
            String name = c.get("name").asText();
            JsonNode actual;
            try {
                actual = execute(profileId, c);
            } catch (CommitmentFormatException e) {
                failures.add(name + ": expected success, got " + e.reason());
                continue;
            } catch (RuntimeException e) {
                failures.add(name + ": expected success, got " + e);
                continue;
            }
            // ObjectNode equality ignores member order and keeps array order.
            if (!c.get("expected").equals(actual)) {
                failures.add(name + ": expected " + c.get("expected") + ", got " + actual);
            }
        }
        for (JsonNode c : file.get("negative")) {
            String name = c.get("name").asText();
            String error = c.get("error").asText();
            try {
                JsonNode actual = execute(profileId, c);
                if (!(error.equals("OPENING_MISMATCH") && result("false").equals(actual))) {
                    failures.add(name + ": expected " + error + ", got " + actual);
                }
            } catch (CommitmentFormatException e) {
                if (!e.reason().name().equals(error)) {
                    failures.add(name + ": expected " + error + ", got " + e.reason() + " (" + e.getMessage() + ")");
                }
            } catch (RuntimeException e) {
                failures.add(name + ": expected " + error + ", got " + e);
            }
        }
        return failures;
    }

    private static JsonNode execute(String profileId, JsonNode c) {
        String op = c.get("operation").asText();
        JsonNode in = c.get("input");
        return switch (profileId) {
            case "pedersen-jubjub-v1" -> scalar(op, in);
            case "pedersen-jubjub-bytes-v1" -> bytes(op, in);
            default -> vector(op, in);
        };
    }

    private static JsonNode scalar(String op, JsonNode in) {
        CommitmentCodec<PedersenScalarCommitment> codec = PedersenScalarCommitment.CODEC;
        return switch (op) {
            case "decodePoint" -> {
                byte[] b = hex(in, "pointHex");
                yield coordinates(agree("decodePoint", List.of(() -> codec.decodePoint(b).point(),
                        () -> PedersenScalarCommitment.decode(b).point(), () -> PedersenCommitment.decode(b))));
            }
            case "commit" -> point(PedersenCommitment.commitScalar(integer(in, "value"), integer(in, "blinding")));
            case "commitLegacy" -> object(Map.of("pointHex",
                    HEX.formatHex(PedersenCommitment.commit(integer(in, "value"), integer(in, "blinding")).toBytes())));
            case "verifyOpening" -> {
                // §13.3 order: configuration (amountBits is read), then the point, then the method.
                Integer amountBits = in.has("amountBits") ? Integer.parseInt(text(in, "amountBits")) : null;
                PedersenScalarCommitment c = codec.decodePoint(hex(in, "pointHex"));
                boolean ok = amountBits == null
                        ? PedersenCommitment.verifyScalar(c, integer(in, "value"), integer(in, "blinding"))
                        : PedersenCommitment.verifyScalar(c, integer(in, "value"), integer(in, "blinding"), amountBits);
                yield result(String.valueOf(ok));
            }
            case "encodeOpening" -> object(Map.of("openingHex",
                    HEX.formatHex(PedersenScalarOpening.of(integer(in, "value"), integer(in, "blinding")).encode())));
            case "decodeOpening" -> {
                PedersenScalarOpening o = PedersenScalarOpening.decode(hex(in, "openingHex"));
                yield object(Map.of("value", o.value().toString(), "blinding", o.blinding().toString()));
            }
            case "encodeEnvelope" -> envelope(codec.decodePoint(hex(in, "pointHex")));
            case "decodeEnvelope" -> point(CommitmentEnvelope.decode(hex(in, "envelopeHex"), codec));
            case "relation" -> {
                List<PedersenScalarCommitment> p = new ArrayList<>();
                for (JsonNode b : in.get("pointsHex")) p.add(codec.decodePoint(HEX.parseHex(b.asText())));
                yield point(switch (text(in, "op")) {
                    case "add" -> p.get(0).add(p.get(1));
                    case "subtract" -> p.get(0).subtract(p.get(1));
                    default -> p.get(0).negate();
                });
            }
            default -> throw new IllegalStateException(op);
        };
    }

    private static JsonNode bytes(String op, JsonNode in) {
        CommitmentCodec<PedersenBytesCommitment> codec = PedersenBytesCommitment.CODEC;
        return switch (op) {
            case "decodePoint" -> {
                byte[] b = hex(in, "pointHex");
                yield coordinates(agree("decodePoint", List.of(() -> codec.decodePoint(b).point(),
                        () -> PedersenBytesCommitment.decode(b).point(), () -> PedersenCommitment.decode(b))));
            }
            case "commit" -> {
                byte[] payload = payload(in.get("payload"));
                BigInteger r = integer(in, "blinding");
                try {
                    if (in.has("declaredLength")) {
                        yield point(PedersenCommitment.commitBytes(new ByteArrayInputStream(payload),
                                Long.parseLong(text(in, "declaredLength")), r));
                    }
                    if (in.has("maxBytes")) {
                        yield point(PedersenCommitment.commitBytesToEnd(new ByteArrayInputStream(payload),
                                Long.parseLong(text(in, "maxBytes")), r));
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
                yield point(PedersenCommitment.commitBytes(payload, r));
            }
            case "hashToScalar" -> {
                byte[] payload = payload(in.get("payload"));
                byte[][] im = PedersenBytesHash.intermediatesForTesting(payload);
                Map<String, String> out = new LinkedHashMap<>();
                out.put("b0Hex", HEX.formatHex(im[0]));
                out.put("b1Hex", HEX.formatHex(im[1]));
                out.put("b2Hex", HEX.formatHex(im[2]));
                out.put("uniformBytesHex", HEX.formatHex(im[3]));
                out.put("scalar", PedersenBytesHash.hashToScalar(payload).toString());
                yield object(out);
            }
            case "verifyOpening" -> {
                PedersenBytesCommitment c = codec.decodePoint(hex(in, "pointHex"));
                byte[] payload = payload(in.get("payload"));
                BigInteger r = integer(in, "blinding");
                // The array and both stream forms must give the same verdict or the same class.
                yield result(agreeOn("verifyBytes", List.of(
                        () -> String.valueOf(PedersenCommitment.verifyBytes(c, payload, r)),
                        () -> io(() -> String.valueOf(PedersenCommitment.verifyBytes(c,
                                new ByteArrayInputStream(payload), payload.length, r))),
                        () -> io(() -> String.valueOf(PedersenCommitment.verifyBytesToEnd(c,
                                new ByteArrayInputStream(payload), payload.length, r))))));
            }
            case "encodeOpening" -> object(Map.of("openingHex", HEX.formatHex(PedersenBlinding.encode(integer(in, "blinding")))));
            case "decodeOpening" -> object(Map.of("blinding", PedersenBlinding.decode(hex(in, "openingHex")).toString()));
            case "encodeEnvelope" -> envelope(codec.decodePoint(hex(in, "pointHex")));
            case "decodeEnvelope" -> point(CommitmentEnvelope.decode(hex(in, "envelopeHex"), codec));
            default -> throw new IllegalStateException(op);
        };
    }

    private static JsonNode vector(String op, JsonNode in) {
        // §13.3 step 1: schema, then policySchema, then the policy (on policySchema when present), then the codec.
        PedersenVectorSchema schema = schema(in.get("schema"));
        PedersenVectorSchema policySchema = in.has("policySchema") ? schema(in.get("policySchema")) : schema;
        PedersenVectorBoundPolicy policy = in.has("policy") ? policy(in.get("policy"), policySchema) : null;
        CommitmentCodec<PedersenVectorCommitment> codec = PedersenVectorCommitment.codec(schema);
        return switch (op) {
            case "configurePolicy" -> result("ok");
            case "decodePoint" -> {
                byte[] b = hex(in, "pointHex");
                yield coordinates(agree("decodePoint", List.of(() -> codec.decodePoint(b).point(),
                        () -> PedersenVectorCommitment.decode(schema, b).point())));
            }
            case "commit" -> point(PedersenVectorCommitment.commit(schema, integers(in, "values"), integer(in, "blinding")));
            case "verifyOpening" -> {
                PedersenVectorCommitment c = codec.decodePoint(hex(in, "pointHex"));
                yield result(String.valueOf(c.verifyOpening(integers(in, "values"), integer(in, "blinding"), policy)));
            }
            case "encodeOpening" -> object(Map.of("openingHex", HEX.formatHex(
                    PedersenVectorOpening.of(policy, integers(in, "values"), integer(in, "blinding")).encode())));
            case "decodeOpening" -> {
                PedersenVectorOpening o = PedersenVectorOpening.decode(hex(in, "openingHex"), policy);
                if (o.policy() != policy) throw new AssertionError("decoded opening carries another policy");
                ObjectNode out = JSON.createObjectNode();
                out.set("schema", schemaJson(o.policy().schema()));
                // The policy kind is configuration the opening does not carry: it is the input's.
                out.set("policy", in.get("policy").deepCopy());
                ArrayNode values = out.putArray("values");
                for (BigInteger v : o.values()) values.add(v.toString());
                out.put("blinding", o.blinding().toString());
                yield out;
            }
            case "encodeEnvelope" -> envelope(codec.decodePoint(hex(in, "pointHex")));
            case "decodeEnvelope" -> point(CommitmentEnvelope.decode(hex(in, "envelopeHex"), codec));
            case "relation" -> {
                List<PedersenVectorCommitment> p = new ArrayList<>();
                for (JsonNode b : in.get("pointsHex")) p.add(codec.decodePoint(HEX.parseHex(b.asText())));
                yield point(text(in, "op").equals("add") ? p.get(0).add(p.get(1)) : p.get(0).subtract(p.get(1)));
            }
            default -> throw new IllegalStateException(op);
        };
    }

    // ---- field readers (spec §13.2; shapes already validated) ----

    private static PedersenVectorSchema schema(JsonNode node) {
        List<PedersenVectorSchema.Entry> entries = new ArrayList<>();
        for (JsonNode e : node.get("entries")) {
            entries.add(new PedersenVectorSchema.Entry(e.get("label").asText(), Integer.parseInt(e.get("width").asText())));
        }
        return PedersenVectorSchema.of(node.get("id").asText(), Integer.parseInt(node.get("version").asText()), entries);
    }

    private static ObjectNode schemaJson(PedersenVectorSchema schema) {
        ObjectNode out = JSON.createObjectNode();
        out.put("id", schema.id());
        out.put("version", String.valueOf(schema.version()));
        ArrayNode entries = out.putArray("entries");
        for (PedersenVectorSchema.Entry e : schema.entries()) {
            entries.addObject().put("label", e.label()).put("width", String.valueOf(e.width()));
        }
        return out;
    }

    private static PedersenVectorBoundPolicy policy(JsonNode node, PedersenVectorSchema schema) {
        return switch (node.get("kind").asText()) {
            case "schema-widths" -> PedersenVectorBoundPolicy.schemaWidths(schema);
            case "residue-only" -> PedersenVectorBoundPolicy.residueOnly(schema);
            default -> PedersenVectorBoundPolicy.widened(schema, Integer.parseInt(node.get("addedTerms").asText()));
        };
    }

    private static byte[] payload(JsonNode node) {
        if (node.has("hex")) return HEX.parseHex(node.get("hex").asText());
        int length = Integer.parseInt(node.get("length").asText());
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) out[i] = (byte) (131L * i + 17);
        return out;
    }

    private static String text(JsonNode in, String field) {
        return in.get(field).asText();
    }

    private static byte[] hex(JsonNode in, String field) {
        return HEX.parseHex(text(in, field));
    }

    private static BigInteger integer(JsonNode in, String field) {
        return new BigInteger(text(in, field));
    }

    private static List<BigInteger> integers(JsonNode in, String field) {
        List<BigInteger> out = new ArrayList<>();
        for (JsonNode v : in.get(field)) out.add(new BigInteger(v.asText()));
        return out;
    }

    // ---- results ----

    private static ObjectNode object(Map<String, String> fields) {
        ObjectNode out = JSON.createObjectNode();
        fields.forEach(out::put);
        return out;
    }

    private static ObjectNode result(String value) {
        return JSON.createObjectNode().put("result", value);
    }

    private static ObjectNode point(Commitment c) {
        return object(Map.of("pointHex", HEX.formatHex(c.toPointBytes())));
    }

    private static ObjectNode envelope(Commitment c) {
        return object(Map.of("envelopeHex", HEX.formatHex(CommitmentEnvelope.encode(c))));
    }

    private static ObjectNode coordinates(JubjubPoint p) {
        return object(Map.of("uHex", HEX.formatHex(PedersenScalarCommitmentTest.i2osp(p.affineU())),
                "vHex", HEX.formatHex(PedersenScalarCommitmentTest.i2osp(p.affineV()))));
    }

    // ---- helpers ----

    /** Runs every strict decoder of a profile (spec §12.3); all must give the same point or class. */
    private static JubjubPoint agree(String what, List<Supplier<JubjubPoint>> decoders) {
        List<Supplier<String>> outcomes = new ArrayList<>();
        JubjubPoint[] first = new JubjubPoint[1];
        for (Supplier<JubjubPoint> d : decoders) {
            outcomes.add(() -> {
                JubjubPoint p = d.get();
                if (first[0] == null) first[0] = p;
                return HEX.formatHex(p.toBytes());
            });
        }
        agreeOn(what, outcomes);
        return first[0];
    }

    /** All suppliers must return the same value or throw the same error class; returns or rethrows it. */
    private static String agreeOn(String what, List<Supplier<String>> forms) {
        String outcome = null;
        CommitmentFormatException error = null;
        String value = null;
        for (Supplier<String> form : forms) {
            String o;
            try {
                String v = form.get();
                o = "value " + v;
                if (outcome == null) value = v;
            } catch (CommitmentFormatException e) {
                o = "class " + e.reason();
                if (outcome == null) error = e;
            }
            if (outcome == null) {
                outcome = o;
            } else if (!outcome.equals(o)) {
                throw new AssertionError(what + ": forms disagree: " + outcome + " vs " + o);
            }
        }
        if (error != null) throw error;
        return value;
    }

    private interface IoSupplier<T> {
        T get() throws IOException;
    }

    private static <T> T io(IoSupplier<T> op) {
        try {
            return op.get();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void assertInvalid(String profileId, String caseName, Consumer<JsonNode> mutation) throws IOException {
        ObjectNode file = load(profileId).deepCopy();
        assertEquals(List.of(), run(file), profileId + " before mutation");
        if (caseName == null) {
            mutation.accept(file);
        } else {
            JsonNode target = null;
            for (String kind : List.of("positive", "negative")) {
                for (JsonNode c : file.get(kind)) {
                    if (c.get("name").asText().equals(caseName)) target = c;
                }
            }
            assertTrue(target != null, "fixture case " + caseName + " exists");
            mutation.accept(target);
        }
        assertThrows(IllegalStateException.class, () -> run(file), profileId + "/" + caseName);
    }

    private static JsonNode reverseKeys(JsonNode node) {
        if (node.isObject()) {
            List<String> keys = new ArrayList<>();
            node.fieldNames().forEachRemaining(keys::add);
            ObjectNode out = JSON.createObjectNode();
            for (int i = keys.size() - 1; i >= 0; i--) out.set(keys.get(i), reverseKeys(node.get(keys.get(i))));
            return out;
        }
        if (node.isArray()) {
            ArrayNode out = JSON.createArrayNode();
            for (JsonNode x : node) out.add(reverseKeys(x));
            return out;
        }
        return node;
    }

    private static JsonNode load(String profileId) throws IOException {
        try (InputStream input = CommitmentProfileVectorsTest.class.getResourceAsStream(DIR + profileId + ".json")) {
            if (input == null) throw new IllegalStateException("missing vector file " + profileId);
            return JSON.readTree(input);
        }
    }
}
