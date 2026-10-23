package org.zeroj.bls12381.pedersen;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Predicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M3: runs every case of the two BLS12-381 G1 {@code zeroj-commitment-vectors-v1} files
 * ({@code commitment-profiles-v1} §13) through the public API of {@link G1Pedersen#pureJava()}, with
 * the shared {@link G1VectorRunner} (the blst provider runs the same cases in zeroj-blst).
 *
 * <p>The files are written by {@code pedersen-g1-reference/emit_g1_commitment_vectors_v1.py}, an
 * independent Python implementation of the specs; nothing here derives an expected value from the
 * code under test. Self-tests confirm the runner notices mutated expectations and rejects invalid
 * fixtures, and that the result does not depend on JSON object key order.
 */
class G1CommitmentProfileVectorsTest {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    @ParameterizedTest
    @ValueSource(strings = {G1VectorRunner.SCALAR, G1VectorRunner.BYTES})
    @DisplayName("Every positive and negative case of the independent G1 vector file holds against the pure-Java API")
    void vectors(String profileId) throws IOException {
        JsonNode file = G1VectorRunner.load(profileId);
        assertEquals(profileId, file.path("profileId").asText());
        G1VectorRunner.Report report = G1VectorRunner.run(file, G1Pedersen.pureJava());
        assertEquals(List.of(), report.failures(), profileId + ": " + report.failures().size() + " failing cases");
        assertEquals(file.get("positive").size() + file.get("negative").size(), report.executed(), "every case ran");
        assertTrue(file.get("positive").size() >= 50, "positive cases");
        assertTrue(file.get("negative").size() >= 100, "negative cases");
    }

    @Test
    @DisplayName("Every file covers every operation of its kind and every error class the kind can produce")
    void coverage() throws IOException {
        Map<String, Set<String>> errors = Map.of(
                G1VectorRunner.SCALAR, Set.of("MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR",
                        "OUT_OF_RANGE", "PROFILE_MISMATCH", "INVALID_CONFIGURATION", "OPENING_MISMATCH"),
                G1VectorRunner.BYTES, Set.of("MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "NON_CANONICAL_SCALAR",
                        "LENGTH_OUT_OF_RANGE", "PROFILE_MISMATCH", "OPENING_MISMATCH"));
        // Operations with a strict check that a negative case must exercise (§13.4).
        Map<String, Set<String>> negativeOperations = Map.of(
                G1VectorRunner.SCALAR, Set.of("decodePoint", "commit", "verifyOpening", "encodeOpening",
                        "decodeOpening", "encodeEnvelope", "decodeEnvelope", "relation", "publicDelta"),
                G1VectorRunner.BYTES, Set.of("decodePoint", "commit", "verifyOpening", "encodeOpening",
                        "decodeOpening", "encodeEnvelope", "decodeEnvelope"));
        for (String profileId : G1VectorRunner.PROFILES) {
            JsonNode file = G1VectorRunner.load(profileId);
            Set<String> positiveOps = new TreeSet<>();
            Set<String> negativeOps = new TreeSet<>();
            Set<String> classes = new TreeSet<>();
            for (JsonNode c : file.get("positive")) positiveOps.add(c.get("operation").asText());
            for (JsonNode c : file.get("negative")) {
                negativeOps.add(c.get("operation").asText());
                classes.add(c.get("error").asText());
            }
            assertEquals(new TreeSet<>(G1VectorRunner.operations(profileId)), positiveOps, profileId + " positive operations");
            assertEquals(new TreeSet<>(negativeOperations.get(profileId)), negativeOps, profileId + " negative operations");
            assertEquals(new TreeSet<>(errors.get(profileId)), classes, profileId + " error classes");
        }

        // §13.4 shapes a reader can check without recomputing anything.
        JsonNode scalar = G1VectorRunner.load(G1VectorRunner.SCALAR);
        assertTrue(any(scalar, "positive", c -> c.get("operation").asText().equals("decodePoint")
                && c.get("expected").has("identity")), "identity decodePoint positive");
        for (String bits : List.of("0", "255")) {
            assertTrue(any(scalar, "negative", c -> c.get("operation").asText().equals("verifyOpening")
                    && bits.equals(c.get("input").path("amountBits").asText())
                    && c.get("error").asText().equals("INVALID_CONFIGURATION")), "amountBits " + bits);
        }
        // Registry r7 §13.4: deltaBits 254 is invalid too (a delta and its alias δ − q would both pass).
        for (String bits : List.of("0", "254", "255")) {
            assertTrue(any(scalar, "negative", c -> c.get("operation").asText().equals("publicDelta")
                    && bits.equals(c.get("input").path("deltaBits").asText())
                    && c.get("error").asText().equals("INVALID_CONFIGURATION")), "deltaBits " + bits);
        }
        assertTrue(any(scalar, "positive", c -> c.get("operation").asText().equals("verifyOpening")
                && "254".equals(c.get("input").path("amountBits").asText())), "amountBits 254 accepted");
        JsonNode bytes = G1VectorRunner.load(G1VectorRunner.BYTES);
        for (String field : List.of("declaredLength", "maxBytes")) {
            assertTrue(any(bytes, "positive", c -> c.get("input").has(field)), field + " positive");
            assertTrue(any(bytes, "negative", c -> c.get("input").has(field)
                    && c.get("error").asText().equals("LENGTH_OUT_OF_RANGE")), field + " LENGTH_OUT_OF_RANGE");
        }
        assertTrue(any(bytes, "positive", c -> c.get("operation").asText().equals("hashToScalar")
                && "".equals(c.get("input").get("payload").path("hex").asText("x"))), "hashToScalar of the empty payload");
        assertTrue(any(bytes, "positive", c -> c.get("operation").asText().equals("hashToScalar")
                && c.get("input").get("payload").has("pattern")
                && Integer.parseInt(c.get("input").get("payload").get("length").asText()) > 64),
                "hashToScalar of a pattern payload longer than a SHA-256 block");
    }

    @Test
    @DisplayName("The runner's spec constants equal the implementation's (MAX_PAYLOAD_BYTES, q)")
    void specConstants() {
        assertEquals(G1PedersenBytesHash.MAX_PAYLOAD_BYTES, G1VectorRunner.SPEC_MAX_PAYLOAD_BYTES);
        assertEquals(G1PedersenStrict.Q, G1VectorRunner.SPEC_Q);
    }

    @Test
    @DisplayName("Self-test: the runner reports changed expected values, changed error classes and a wrong verdict")
    void runnerDetectsMutations() throws IOException {
        String s = G1VectorRunner.SCALAR;
        String b = G1VectorRunner.BYTES;
        // Changed expected values: every value-producing scalar operation, the bytes commit, every
        // hashToScalar field.
        for (String op : List.of("commit", "publicDelta", "relation", "decodeEnvelope")) {
            assertDetected(s, "positive", operation(op), file -> flipHex(theCase(file).get("expected"), "pointHex"));
        }
        for (String field : List.of("xHex", "yHex")) {
            assertDetected(s, "positive", operation("decodePoint").and(c -> c.get("expected").has(field)),
                    file -> flipHex(theCase(file).get("expected"), field));
        }
        assertDetected(s, "positive", operation("decodePoint").and(c -> c.get("expected").has("identity")), file -> {
            ObjectNode expected = (ObjectNode) theCase(file).get("expected");
            expected.remove("identity");
            expected.put("xHex", "00".repeat(48)).put("yHex", "00".repeat(47) + "02");
        });
        assertDetected(s, "positive", operation("encodeOpening"), file -> flipHex(theCase(file).get("expected"), "openingHex"));
        assertDetected(s, "positive", operation("encodeEnvelope"), file -> flipHex(theCase(file).get("expected"), "envelopeHex"));
        assertDetected(s, "positive", operation("decodeOpening"),
                file -> ((ObjectNode) theCase(file).get("expected")).put("value", "7"));
        assertDetected(b, "positive", operation("commit"), file -> flipHex(theCase(file).get("expected"), "pointHex"));
        for (String field : List.of("b0Hex", "b1Hex", "b2Hex", "uniformBytesHex")) {
            assertDetected(b, "positive", operation("hashToScalar"), file -> flipHex(theCase(file).get("expected"), field));
        }
        assertDetected(b, "positive", operation("hashToScalar"),
                file -> ((ObjectNode) theCase(file).get("expected")).put("scalar", "1"));
        assertDetected(b, "positive", operation("decodeOpening"),
                file -> ((ObjectNode) theCase(file).get("expected")).put("blinding", "7"));

        for (String profileId : G1VectorRunner.PROFILES) {
            JsonNode file = G1VectorRunner.load(profileId);
            // A changed error class, for every class present in the file. (LENGTH_OUT_OF_RANGE is tied to
            // its bound by the streams rule, so changing only its class is an invalid fixture; it is
            // covered by the input mutation below.)
            for (String from : List.of("NON_CANONICAL_SCALAR", "MALFORMED_ENCODING", "NOT_IN_SUBGROUP", "PROFILE_MISMATCH",
                    "OUT_OF_RANGE", "INVALID_CONFIGURATION", "OPENING_MISMATCH")) {
                if (!any(file, "negative", c -> c.get("error").asText().equals(from))) continue;
                String to = from.equals("MALFORMED_ENCODING") ? "NOT_IN_SUBGROUP" : "MALFORMED_ENCODING";
                assertDetected(profileId, "negative", c -> c.get("error").asText().equals(from)
                                && !c.get("input").has("declaredLength") && !c.get("input").has("maxBytes"),
                        f -> theCase(f).put("error", to));
            }
            // A false verdict reported as true, and a rejected point reported as the identity.
            assertDetected(profileId, "negative", c -> c.get("error").asText().equals("OPENING_MISMATCH"),
                    f -> toPositive(f, NODES.objectNode().put("result", "true")));
            assertDetected(profileId, "negative", operation("decodePoint"),
                    f -> toPositive(f, NODES.objectNode().put("identity", "true")));
        }
        // A LENGTH_OUT_OF_RANGE case whose blinding becomes q: the blinding check precedes the bound
        // (pedersen-bls12-381-g1-v1.md §8), so the class changes and the runner must notice.
        for (String field : List.of("declaredLength", "maxBytes")) {
            assertDetected(b, "negative", c -> c.get("error").asText().equals("LENGTH_OUT_OF_RANGE") && c.get("input").has(field),
                    f -> ((ObjectNode) theCase(f).get("input")).put("blinding", G1VectorRunner.SPEC_Q.toString()));
        }
    }

    @Test
    @DisplayName("Reordering object keys in a valid file changes nothing (JSON object members are unordered)")
    void keyOrderIsIrrelevant() throws IOException {
        for (String profileId : G1VectorRunner.PROFILES) {
            JsonNode original = G1VectorRunner.load(profileId);
            JsonNode reordered = reverseKeys(original);
            assertFalse(original.toString().equals(reordered.toString()), "the reordering changed the serialization");
            G1VectorRunner.Report report = G1VectorRunner.run(reordered, G1Pedersen.pureJava());
            assertEquals(List.of(), report.failures(), profileId);
            assertEquals(G1VectorRunner.run(original, G1Pedersen.pureJava()).outcomes(), report.outcomes(), profileId);
        }
    }

    @Test
    @DisplayName("Strict JSON: duplicate keys and trailing content are rejected by the parser")
    void strictJson() {
        assertThrows(JsonProcessingException.class, () -> G1VectorRunner.parse("{\"a\": \"1\", \"a\": \"2\"}"));
        assertThrows(JsonProcessingException.class, () -> G1VectorRunner.parse("{\"a\": \"1\"} {\"b\": \"2\"}"));
    }

    @Test
    @DisplayName("Fixture validation rejects the whole file for every malformed fixture shape")
    void fixtureValidation() throws IOException {
        String s = G1VectorRunner.SCALAR;
        String b = G1VectorRunner.BYTES;
        // §13.2: a JSON number, a boolean and a null anywhere.
        assertInvalid(s, "decode-point-identity", c -> ((ObjectNode) c.get("input")).put("pointHex", 1));
        assertInvalid(s, "decode-point-identity", c -> ((ObjectNode) c.get("expected")).put("identity", true));
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c.get("input")).putNull("value"));
        assertInvalid(s, null, file -> ((ObjectNode) file.get("generator")).put("python", 3));
        // Integers: non-canonical decimal forms, and the 32- and 64-bit domains of §13.2.
        for (String bad : List.of("-0", "01", "+1", "1.0", "1e3", " 1", "0x1", "")) {
            assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c.get("input")).put("value", bad));
        }
        assertInvalid(s, "verify-amount-bits-1-overflow", c -> ((ObjectNode) c.get("input")).put("amountBits", "2147483648"));
        assertInvalid(s, "public-delta-bits-1-plus-2pow", c -> ((ObjectNode) c.get("input")).put("deltaBits", "-2147483649"));
        assertInvalid(b, "commit-declared-length-long-max",
                c -> ((ObjectNode) c.get("input")).put("declaredLength", "9223372036854775808"));
        // Unknown and missing fields at every level; an unknown operation (G1 has no legacy commit).
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c).put("note", "x"));
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c.get("input")).put("amountBits", "64"));
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c.get("input")).remove("blinding"));
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c).put("operation", "commitLegacy"));
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c.get("expected")).put("extra", "1"));
        assertInvalid(s, null, file -> ((ObjectNode) file).put("extra", "1"));
        assertInvalid(s, null, file -> ((ObjectNode) file).put("schema", "zeroj-commitment-vectors-v2"));
        assertInvalid(s, null, file -> ((ObjectNode) file.get("spec").get(0)).put("extra", "1"));
        assertInvalid(b, "commit-blinding-q", c -> ((ObjectNode) c.get("input").get("payload")).put("extra", "1"));
        assertInvalid(b, "hash-to-scalar-pattern-1", c -> ((ObjectNode) c.get("input").get("payload")).put("pattern", "i"));
        assertInvalid(b, "hash-to-scalar-pattern-1", c -> ((ObjectNode) c.get("input").get("payload")).put("length", "-1"));
        // A negative case with an expected value, a positive case with an error, an unknown class.
        assertInvalid(s, "commit-value-q", c -> ((ObjectNode) c).set("expected", NODES.objectNode().put("pointHex", "00")));
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c).put("error", "MALFORMED_ENCODING"));
        assertInvalid(s, "commit-value-q", c -> ((ObjectNode) c).put("error", "NOT_A_CLASS"));
        // Duplicate case names (across positive and negative).
        assertInvalid(s, "commit-value-q", c -> ((ObjectNode) c).put("name", "commit-zero-zero"));
        // Relation: wrong arity, an unknown operator a point failure would otherwise mask, arithmetic on bytes.
        assertInvalid(s, "relation-negate-mixed-order", c -> ((ArrayNode) c.get("input").get("pointsHex")).add("00"));
        assertInvalid(s, "relation-order-first-point-first", c -> ((ObjectNode) c.get("input")).put("op", "bogus"));
        assertInvalid(s, "relation-add-wraparound", c -> ((ArrayNode) c.get("input").get("pointsHex")).remove(1));
        // decodePoint: identity mixed with coordinates, identity "false", a short coordinate.
        assertInvalid(s, "decode-point-identity", c -> ((ObjectNode) c.get("expected")).put("xHex", "00".repeat(48)));
        assertInvalid(s, "decode-point-identity", c -> ((ObjectNode) c.get("expected")).put("identity", "false"));
        assertInvalid(s, "decode-point-base-g", c -> ((ObjectNode) c.get("expected")).put("xHex", "00".repeat(47)));
        assertInvalid(s, "decode-point-base-g", c -> ((ObjectNode) c.get("expected")).remove("yHex"));
        // Expected values of the wrong shape; a verdict other than "true" in a positive case.
        assertInvalid(s, "commit-zero-zero", c -> ((ObjectNode) c.get("expected")).put("pointHex", "c0"));
        assertInvalid(s, "verify-identity-zero-zero", c -> ((ObjectNode) c.get("expected")).put("result", "false"));
        assertInvalid(s, "verify-identity-zero-zero", c -> ((ObjectNode) c.get("expected")).put("result", "ok"));
        assertInvalid(b, "hash-to-scalar-empty", c -> ((ObjectNode) c.get("expected")).put("uniformBytesHex", "00".repeat(32)));
        // Hex: upper case and odd length.
        assertInvalid(s, "decode-point-identity", c -> ((ObjectNode) c.get("input")).put("pointHex", "C0" + "00".repeat(47)));
        assertInvalid(s, "decode-point-length-0", c -> ((ObjectNode) c.get("input")).put("pointHex", "0"));
        // The expected profile: another registered profile, and an invalid identifier.
        assertInvalid(s, "envelope-decode-identity", c -> ((ObjectNode) c.get("input")).put("expectedProfileId", b));
        assertInvalid(s, "envelope-decode-identity", c -> ((ObjectNode) c.get("input")).put("expectedProfileId", "Bad Id"));
        // The streams rule: an out-of-range bound outside a LENGTH_OUT_OF_RANGE case, a declared length that
        // disagrees with the payload, a maximum below it, both bounds together, a non-empty payload in a
        // LENGTH_OUT_OF_RANGE case, and a length field on an operation that has none.
        assertInvalid(b, "commit-blinding-q", c -> ((ObjectNode) c.get("input")).put("declaredLength", "-1"));
        assertInvalid(b, "commit-abc-12345-declared-length", c -> ((ObjectNode) c.get("input")).put("declaredLength", "4"));
        assertInvalid(b, "commit-abc-12345-max-bytes-3", c -> ((ObjectNode) c.get("input")).put("maxBytes", "2"));
        assertInvalid(b, "commit-abc-12345-declared-length", c -> ((ObjectNode) c.get("input")).put("maxBytes", "3"));
        assertInvalid(b, "commit-declared-length-minus-1",
                c -> ((ObjectNode) c.get("input")).set("payload", NODES.objectNode().put("hex", "00")));
        assertInvalid(b, "hash-to-scalar-empty", c -> ((ObjectNode) c.get("input")).put("declaredLength", "0"));
    }

    // ---- helpers ----

    /**
     * Runs the first case of {@code kind} matching {@code select} alone: unmutated it must pass, and
     * after {@code mutation} (applied to a one-case copy of the file) the runner must report a failure.
     */
    private static void assertDetected(String profileId, String kind, Predicate<JsonNode> select,
                                       Consumer<ObjectNode> mutation) throws IOException {
        JsonNode file = G1VectorRunner.load(profileId);
        String name = null;
        for (JsonNode c : file.get(kind)) {
            if (select.test(c)) {
                name = c.get("name").asText();
                break;
            }
        }
        assertNotNull(name, profileId + ": no " + kind + " case to mutate");
        ObjectNode single = file.deepCopy();
        for (String k : List.of("positive", "negative")) {
            ArrayNode kept = NODES.arrayNode();
            for (JsonNode c : file.get(k)) {
                if (c.get("name").asText().equals(name)) kept.add(c.deepCopy());
            }
            single.set(k, kept);
        }
        assertEquals(List.of(), G1VectorRunner.run(single, G1Pedersen.pureJava()).failures(), profileId + "/" + name);
        mutation.accept(single);
        assertFalse(G1VectorRunner.run(single, G1Pedersen.pureJava()).failures().isEmpty(),
                profileId + "/" + name + ": the mutation went unnoticed");
    }

    /** The only case of a one-case file. */
    private static ObjectNode theCase(ObjectNode single) {
        JsonNode c = single.get("positive").isEmpty() ? single.get("negative").get(0) : single.get("positive").get(0);
        return (ObjectNode) c;
    }

    /** Turns the only (negative) case of a one-case file into a positive case with {@code expected}. */
    private static void toPositive(ObjectNode single, ObjectNode expected) {
        ObjectNode c = (ObjectNode) ((ArrayNode) single.get("negative")).remove(0);
        c.remove("error");
        c.set("expected", expected);
        ((ArrayNode) single.get("positive")).add(c);
    }

    private static Predicate<JsonNode> operation(String operation) {
        return c -> c.get("operation").asText().equals(operation);
    }

    /** Changes the last hex digit of a field while keeping it valid lowercase hex of the same length. */
    private static void flipHex(JsonNode expected, String field) {
        String hex = expected.get(field).asText();
        char last = hex.charAt(hex.length() - 1);
        ((ObjectNode) expected).put(field, hex.substring(0, hex.length() - 1) + (last == '0' ? '1' : '0'));
    }

    private static boolean any(JsonNode file, String kind, Predicate<JsonNode> test) {
        for (JsonNode c : file.get(kind)) {
            if (test.test(c)) return true;
        }
        return false;
    }

    private static void assertInvalid(String profileId, String caseName, Consumer<JsonNode> mutation) throws IOException {
        ObjectNode file = G1VectorRunner.load(profileId).deepCopy();
        G1VectorRunner.validate(file);
        if (caseName == null) {
            mutation.accept(file);
        } else {
            JsonNode target = null;
            for (String kind : List.of("positive", "negative")) {
                for (JsonNode c : file.get(kind)) {
                    if (c.get("name").asText().equals(caseName)) target = c;
                }
            }
            assertNotNull(target, "fixture case " + caseName + " exists");
            mutation.accept(target);
        }
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> G1VectorRunner.run(file, G1Pedersen.pureJava()), profileId + "/" + caseName);
        assertTrue(e.getMessage().startsWith("invalid fixture: "), e.getMessage());
    }

    private static JsonNode reverseKeys(JsonNode node) {
        if (node.isObject()) {
            List<String> keys = new ArrayList<>();
            node.fieldNames().forEachRemaining(keys::add);
            ObjectNode out = NODES.objectNode();
            for (int i = keys.size() - 1; i >= 0; i--) out.set(keys.get(i), reverseKeys(node.get(keys.get(i))));
            return out;
        }
        if (node.isArray()) {
            ArrayNode out = NODES.arrayNode();
            for (JsonNode x : node) out.add(reverseKeys(x));
            return out;
        }
        return node;
    }
}
