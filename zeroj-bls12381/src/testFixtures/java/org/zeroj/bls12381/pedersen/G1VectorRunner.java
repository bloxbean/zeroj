package org.zeroj.bls12381.pedersen;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.zeroj.api.commitment.Commitment;
import org.zeroj.api.commitment.CommitmentCodec;
import org.zeroj.api.commitment.CommitmentEnvelope;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentProfileId;
import org.zeroj.bls12381.ec.G1Point;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * ADR-0060 M3, test fixture: runs the {@code zeroj-commitment-vectors-v1} files of the BLS12-381 G1
 * Pedersen profiles ({@code commitment-profiles-v1} §13) through the public API of a given
 * {@link G1Pedersen} instance, so the pure-Java and blst providers run the same cases with the same
 * code.
 *
 * <p>The files are written by {@code pedersen-g1-reference/emit_g1_commitment_vectors_v1.py}, an
 * independent Python implementation of the spec; nothing here derives an expected value from the
 * code under test. Before any case runs, the whole file is validated against §13.1–§13.3: strict JSON
 * (no duplicate keys, no trailing content), no JSON numbers, the required and allowed fields at every
 * level, value shapes, the integer domains of §13.2, the relation arity, the expected profile and the
 * streams rule. An invalid fixture rejects the whole file with {@link IllegalStateException}.
 *
 * <p>Each positive case must then produce exactly its expected value (compared as JSON, ignoring
 * object key order); each negative case must fail with exactly its error class
 * ({@code OPENING_MISMATCH} is a {@code false} verification). Where the API has several forms of one
 * operation (the strict decoders of a profile; the array, declared-length and read-to-end payload
 * sources), every form runs and all must give the same value or the same class.
 *
 * <p>Test code only: this class is never published (zeroj-bls12381's test-fixtures variants are
 * removed from its Maven component).
 */
public final class G1VectorRunner {

    /** The scalar profile. */
    public static final String SCALAR = "pedersen-bls12-381-g1-v1";
    /** The bytes profile. */
    public static final String BYTES = "pedersen-bls12-381-g1-bytes-v1";
    /** Both G1 profiles, in a fixed order. */
    public static final List<String> PROFILES = List.of(SCALAR, BYTES);

    /** {@code MAX_PAYLOAD_BYTES = 2^61 − 256}, from {@code pedersen-bls12-381-g1-v1.md} §5 (not from the code). */
    public static final long SPEC_MAX_PAYLOAD_BYTES = 2305843009213693696L;

    /** The subgroup order {@code q}, from {@code pedersen-bls12-381-g1-v1.md} §1. */
    static final BigInteger SPEC_Q =
            new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();
    private static final HexFormat HEX = HexFormat.of();
    private static final String DIR = "/test-vectors/commitment-profiles-v1/";
    private static final Pattern HEX_STRING = Pattern.compile("([0-9a-f]{2})*");
    /** A canonical signed decimal: no sign on zero, no leading zeros, no {@code +}. */
    private static final Pattern INTEGER = Pattern.compile("0|-?[1-9][0-9]*");

    private static final int POINT_OCTETS = 48;
    private static final int COORDINATE_OCTETS = 48;

    /** One operation of one profile: required and optional input fields, expected fields (§13.3 table). */
    private record Op(Set<String> required, Set<String> optional, Set<String> expected) {
    }

    private static final Set<String> NONE = Set.of();
    private static final Set<String> POINT = Set.of("pointHex");
    /** Marker for {@code decodePoint}: {@code {xHex, yHex}} or {@code {identity}} (validated separately). */
    private static final Set<String> DECODED = Set.of("xHex", "yHex", "identity");

    private static final Map<String, Map<String, Op>> OPS = Map.of(
            SCALAR, Map.of(
                    "decodePoint", new Op(POINT, NONE, DECODED),
                    "commit", new Op(Set.of("value", "blinding"), NONE, POINT),
                    "verifyOpening", new Op(Set.of("pointHex", "value", "blinding"), Set.of("amountBits"),
                            Set.of("result")),
                    "encodeOpening", new Op(Set.of("value", "blinding"), NONE, Set.of("openingHex")),
                    "decodeOpening", new Op(Set.of("openingHex"), NONE, Set.of("value", "blinding")),
                    "encodeEnvelope", new Op(POINT, NONE, Set.of("envelopeHex")),
                    "decodeEnvelope", new Op(Set.of("envelopeHex", "expectedProfileId"), NONE, POINT),
                    "relation", new Op(Set.of("op", "pointsHex"), NONE, POINT),
                    "publicDelta", new Op(Set.of("pointHex", "delta", "deltaBits"), NONE, POINT)),
            BYTES, Map.of(
                    "decodePoint", new Op(POINT, NONE, DECODED),
                    "commit", new Op(Set.of("payload", "blinding"), Set.of("declaredLength", "maxBytes"), POINT),
                    "hashToScalar", new Op(Set.of("payload"), NONE,
                            Set.of("b0Hex", "b1Hex", "b2Hex", "uniformBytesHex", "scalar")),
                    "verifyOpening", new Op(Set.of("pointHex", "payload", "blinding"), NONE, Set.of("result")),
                    "encodeOpening", new Op(Set.of("blinding"), NONE, Set.of("openingHex")),
                    "decodeOpening", new Op(Set.of("openingHex"), NONE, Set.of("blinding")),
                    "encodeEnvelope", new Op(POINT, NONE, Set.of("envelopeHex")),
                    "decodeEnvelope", new Op(Set.of("envelopeHex", "expectedProfileId"), NONE, POINT)));

    /** Octet lengths of {@code …Hex} fields in a positive case's {@code expected} (spec-fixed shapes). */
    private static final Map<String, Map<String, Integer>> EXPECTED_HEX_OCTETS = Map.of(
            SCALAR, Map.of("pointHex", POINT_OCTETS, "xHex", COORDINATE_OCTETS, "yHex", COORDINATE_OCTETS,
                    "openingHex", 64, "envelopeHex", 74),
            BYTES, Map.of("pointHex", POINT_OCTETS, "xHex", COORDINATE_OCTETS, "yHex", COORDINATE_OCTETS,
                    "openingHex", 32, "envelopeHex", 80,
                    "b0Hex", 32, "b1Hex", 32, "b2Hex", 32, "uniformBytesHex", 48));

    /**
     * The result of running one file.
     *
     * @param failures one message per case whose outcome differs from the file
     * @param outcomes every executed case's actual outcome, by case name, in file order: {@code value <json>}
     *                 for a returned value, {@code class <name>} for a {@link CommitmentFormatException},
     *                 {@code exception <type>} for anything else
     */
    public record Report(List<String> failures, Map<String, String> outcomes) {
        public Report {
            failures = List.copyOf(failures);
            outcomes = Collections.unmodifiableMap(new LinkedHashMap<>(outcomes));
        }

        /** The number of cases executed. */
        public int executed() {
            return outcomes.size();
        }
    }

    private G1VectorRunner() {
    }

    // ---- loading ----

    /** Loads a profile's vector file from the classpath (zeroj-test-vectors resources), strictly parsed. */
    public static JsonNode load(String profileId) throws IOException {
        if (!PROFILES.contains(profileId)) throw new IllegalArgumentException("not a G1 profile: " + profileId);
        try (InputStream input = G1VectorRunner.class.getResourceAsStream(DIR + profileId + ".json")) {
            if (input == null) throw new IllegalStateException("missing vector file " + profileId);
            return JSON.readTree(input);
        }
    }

    /** Parses JSON text with the same strict settings as {@link #load}: duplicate keys and trailing content fail. */
    public static JsonNode parse(String json) throws IOException {
        return JSON.readTree(json);
    }

    /** The operations §13.3 defines for a G1 profile's kind. */
    public static Set<String> operations(String profileId) {
        Map<String, Op> ops = OPS.get(profileId);
        if (ops == null) throw new IllegalArgumentException("not a G1 profile: " + profileId);
        return ops.keySet();
    }

    // ---- validation (spec §13.1–§13.3) ----

    /** Validates a whole file; an invalid fixture throws {@link IllegalStateException}. */
    public static void validate(JsonNode file) {
        requireNoNumbers(file, "$");
        requireObject(file, "$", Set.of("schema", "profileId", "spec", "generator", "positive", "negative"), NONE);
        if (!"zeroj-commitment-vectors-v1".equals(file.get("schema").asText())) invalid("$.schema");
        String profileId = file.get("profileId").asText();
        Map<String, Op> ops = OPS.get(profileId);
        if (ops == null) invalid("unknown profile " + profileId);
        if (!file.get("spec").isArray() || file.get("spec").isEmpty()) invalid("$.spec");
        for (JsonNode s : file.get("spec")) {
            requireObject(s, "$.spec[]", Set.of("path", "date", "sha256"), Set.of("revision"));
            requireHex(s.get("sha256"), "$.spec[].sha256", 32);
        }
        requireObject(file.get("generator"), "$.generator", Set.of("script", "scriptSha256", "python"), NONE);
        if (!file.get("generator").get("script").asText().endsWith("emit_g1_commitment_vectors_v1.py")) {
            invalid("$.generator.script");
        }
        requireHex(file.get("generator").get("scriptSha256"), "$.generator.scriptSha256", 32);
        Set<String> names = new HashSet<>();
        for (String kind : List.of("positive", "negative")) {
            if (!file.get(kind).isArray()) invalid("$." + kind);
            for (JsonNode c : file.get(kind)) {
                if (!c.isObject() || !c.path("name").isTextual() || c.get("name").asText().isEmpty()) {
                    invalid("$." + kind + "[]: case without a name");
                }
                String where = "$." + kind + "[" + c.get("name").asText() + "]";
                boolean positive = kind.equals("positive");
                requireObject(c, where, Set.of("name", "operation", "input", positive ? "expected" : "error"), NONE);
                if (!names.add(c.get("name").asText())) invalid(where + ": duplicate name");
                String operation = c.get("operation").asText();
                Op op = ops.get(operation);
                if (op == null) invalid(where + ": unknown operation " + operation);
                JsonNode in = c.get("input");
                requireObject(in, where + ".input", op.required(), op.optional());
                for (Iterator<Map.Entry<String, JsonNode>> it = in.fields(); it.hasNext(); ) {
                    Map.Entry<String, JsonNode> e = it.next();
                    validateField(profileId, e.getKey(), e.getValue(), where + ".input." + e.getKey());
                }
                validateRelation(operation, in, where);
                if (positive) {
                    JsonNode expected = c.get("expected");
                    if (operation.equals("decodePoint")) {
                        if (expected != null && expected.has("identity")) {
                            requireObject(expected, where + ".expected", Set.of("identity"), NONE);
                        } else {
                            requireObject(expected, where + ".expected", Set.of("xHex", "yHex"), NONE);
                        }
                    } else {
                        requireObject(expected, where + ".expected", op.expected(), NONE);
                    }
                    for (Iterator<Map.Entry<String, JsonNode>> it = expected.fields(); it.hasNext(); ) {
                        Map.Entry<String, JsonNode> e = it.next();
                        String w = where + ".expected." + e.getKey();
                        validateField(profileId, e.getKey(), e.getValue(), w);
                        Integer octets = EXPECTED_HEX_OCTETS.get(profileId).get(e.getKey());
                        if (octets != null) requireHex(e.getValue(), w, octets);
                    }
                } else {
                    try {
                        CommitmentError.valueOf(c.get("error").asText());
                    } catch (IllegalArgumentException e) {
                        invalid(where + ": unknown error class");
                    }
                }
                if (profileId.equals(BYTES)) {
                    validateStreams(c, positive, where);
                }
            }
        }
    }

    private static void validateField(String profileId, String field, JsonNode v, String where) {
        switch (field) {
            case "pointHex", "envelopeHex", "openingHex", "xHex", "yHex", "b0Hex", "b1Hex", "b2Hex",
                 "uniformBytesHex" -> requireHex(v, where);
            case "value", "blinding", "scalar", "delta" -> requireInteger(v, where);
            case "amountBits", "deltaBits" -> requireInt32(v, where);
            case "declaredLength", "maxBytes" -> requireInt64(v, where);
            case "pointsHex" -> {
                if (!v.isArray()) invalid(where + ": not an array");
                for (JsonNode x : v) requireHex(x, where + "[]");
            }
            case "op" -> {
                // Only the scalar profile has arithmetic (pedersen-bls12-381-g1-v1.md §6.4).
                if (!profileId.equals(SCALAR) || !v.isTextual() || !Set.of("add", "subtract", "negate").contains(v.asText())) {
                    invalid(where + ": relation operator");
                }
            }
            case "expectedProfileId" -> {
                // §13.2: a valid identifier; §13.4 (emitter limits): always the file's own profile.
                if (!v.isTextual()) invalid(where);
                try {
                    CommitmentProfileId.of(v.asText());
                } catch (IllegalArgumentException e) {
                    invalid(where + ": not a valid identifier");
                }
                if (!v.asText().equals(profileId)) invalid(where + ": not the file's profile");
            }
            case "result", "identity" -> {
                if (!v.isTextual() || !v.asText().equals("true")) invalid(where + ": must be \"true\"");
            }
            case "payload" -> {
                if (v == null || !v.isObject()) invalid(where + ": not an object");
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
            default -> invalid(where + ": unknown field");
        }
    }

    /** §13.2: {@code add}/{@code subtract} take exactly two points, {@code negate} exactly one. */
    private static void validateRelation(String operation, JsonNode in, String where) {
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
        long length = payloadLength(in.get("payload"));
        boolean lengthCase = !positive && c.get("error").asText().equals("LENGTH_OUT_OF_RANGE");
        if (lengthCase) {
            if (length != 0 || inPayloadRange(bound)) {
                invalid(where + ": a LENGTH_OUT_OF_RANGE case needs an empty payload and an out-of-range bound");
            }
        } else if (declared ? bound != length : bound < length) {
            invalid(where + ": streams rule (declaredLength must equal, maxBytes must cover, the payload length)");
        } else if (!inPayloadRange(bound)) {
            invalid(where + ": an out-of-range bound in a case whose class is not LENGTH_OUT_OF_RANGE");
        }
    }

    private static boolean inPayloadRange(long bound) {
        return bound >= 0 && bound <= SPEC_MAX_PAYLOAD_BYTES;
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

    private static void requireHex(JsonNode v, String where, int octets) {
        requireHex(v, where);
        if (v.asText().length() != 2 * octets) invalid(where + ": not " + octets + " octets");
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

    /**
     * Validates {@code file}, then runs every case through {@code pedersen}.
     *
     * @throws IllegalStateException if the file is not a valid fixture (nothing is executed)
     */
    public static Report run(JsonNode file, G1Pedersen pedersen) {
        Objects.requireNonNull(pedersen, "pedersen");
        validate(file);
        String profileId = file.get("profileId").asText();
        List<String> failures = new ArrayList<>();
        Map<String, String> outcomes = new LinkedHashMap<>();
        for (JsonNode c : file.get("positive")) {
            String name = c.get("name").asText();
            JsonNode actual;
            try {
                actual = execute(profileId, c, pedersen);
            } catch (CommitmentFormatException e) {
                outcomes.put(name, "class " + e.reason());
                failures.add(name + ": expected success, got " + e.reason() + " (" + e.getMessage() + ")");
                continue;
            } catch (RuntimeException e) {
                outcomes.put(name, "exception " + e);
                failures.add(name + ": expected success, got " + e);
                continue;
            }
            outcomes.put(name, "value " + actual);
            // ObjectNode equality ignores member order and keeps array order.
            if (!c.get("expected").equals(actual)) {
                failures.add(name + ": expected " + c.get("expected") + ", got " + actual);
            }
        }
        for (JsonNode c : file.get("negative")) {
            String name = c.get("name").asText();
            String error = c.get("error").asText();
            try {
                JsonNode actual = execute(profileId, c, pedersen);
                outcomes.put(name, "value " + actual);
                if (!(error.equals("OPENING_MISMATCH") && result("false").equals(actual))) {
                    failures.add(name + ": expected " + error + ", got " + actual);
                }
            } catch (CommitmentFormatException e) {
                outcomes.put(name, "class " + e.reason());
                if (!e.reason().name().equals(error)) {
                    failures.add(name + ": expected " + error + ", got " + e.reason() + " (" + e.getMessage() + ")");
                }
            } catch (RuntimeException e) {
                outcomes.put(name, "exception " + e);
                failures.add(name + ": expected " + error + ", got " + e);
            }
        }
        return new Report(failures, outcomes);
    }

    private static JsonNode execute(String profileId, JsonNode c, G1Pedersen pedersen) {
        String op = c.get("operation").asText();
        JsonNode in = c.get("input");
        return profileId.equals(SCALAR) ? scalar(op, in, pedersen) : bytes(op, in, pedersen);
    }

    private static JsonNode scalar(String op, JsonNode in, G1Pedersen pedersen) {
        CommitmentCodec<G1PedersenCommitment> codec = G1PedersenCommitment.CODEC;
        return switch (op) {
            case "decodePoint" -> {
                byte[] b = hex(in, "pointHex");
                yield coordinates(agreeOnPoint(b, List.of(
                        () -> decoded(codec.decodePoint(b)), () -> decoded(G1PedersenCommitment.decode(b)))));
            }
            case "commit" -> point(pedersen.commitScalar(integer(in, "value"), integer(in, "blinding")));
            case "verifyOpening" -> {
                // §13.3 order: configuration (amountBits is read), then the point, then the method's own order.
                Integer amountBits = in.has("amountBits") ? Integer.parseInt(text(in, "amountBits")) : null;
                G1PedersenCommitment c = codec.decodePoint(hex(in, "pointHex"));
                boolean ok = amountBits == null
                        ? pedersen.verifyScalar(c, integer(in, "value"), integer(in, "blinding"))
                        : pedersen.verifyScalar(c, integer(in, "value"), integer(in, "blinding"), amountBits);
                yield result(String.valueOf(ok));
            }
            case "encodeOpening" -> object(Map.of("openingHex",
                    HEX.formatHex(G1PedersenOpening.of(integer(in, "value"), integer(in, "blinding")).encode())));
            case "decodeOpening" -> {
                G1PedersenOpening o = G1PedersenOpening.decode(hex(in, "openingHex"));
                yield object(Map.of("value", o.value().toString(), "blinding", o.blinding().toString()));
            }
            case "encodeEnvelope" -> envelope(codec.decodePoint(hex(in, "pointHex")));
            case "decodeEnvelope" -> point(CommitmentEnvelope.decode(hex(in, "envelopeHex"),
                    scalarCodec(text(in, "expectedProfileId"))));
            case "relation" -> {
                // §13.3 step 2: the points in index order, each under §10.
                List<G1PedersenCommitment> p = new ArrayList<>();
                for (JsonNode b : in.get("pointsHex")) p.add(codec.decodePoint(HEX.parseHex(b.asText())));
                yield point(switch (text(in, "op")) {
                    case "add" -> p.get(0).add(p.get(1));
                    case "subtract" -> p.get(0).subtract(p.get(1));
                    case "negate" -> p.get(0).negate();
                    default -> throw new IllegalStateException("relation operator");
                });
            }
            case "publicDelta" -> {
                // §13.3: deltaBits is read in step 1, the point decoded in step 2, then
                // withPublicDelta's own order (deltaBits before delta).
                int deltaBits = Integer.parseInt(text(in, "deltaBits"));
                G1PedersenCommitment c = codec.decodePoint(hex(in, "pointHex"));
                yield point(c.withPublicDelta(integer(in, "delta"), deltaBits));
            }
            default -> throw new IllegalStateException(op);
        };
    }

    private static JsonNode bytes(String op, JsonNode in, G1Pedersen pedersen) {
        CommitmentCodec<G1PedersenBytesCommitment> codec = G1PedersenBytesCommitment.CODEC;
        return switch (op) {
            case "decodePoint" -> {
                byte[] b = hex(in, "pointHex");
                yield coordinates(agreeOnPoint(b, List.of(
                        () -> decoded(codec.decodePoint(b)), () -> decoded(G1PedersenBytesCommitment.decode(b)))));
            }
            case "commit" -> object(Map.of("pointHex", agreeOn("commitBytes", commitForms(in, pedersen))));
            case "hashToScalar" -> {
                byte[] payload = payload(in.get("payload"));
                byte[][] im = G1PedersenBytesHash.intermediatesForTesting(payload);
                BigInteger s = G1PedersenBytesHash.hashToScalar(payload);
                // The public bytes path must use this scalar: C(B, r) = C(s, r) (spec §3), r = 0 and 1.
                if (pedersen.supportsGeneration()) {
                    for (BigInteger r : List.of(BigInteger.ZERO, BigInteger.ONE)) {
                        byte[] viaBytes = pedersen.commitBytes(payload, r).toPointBytes();
                        byte[] viaScalar = pedersen.commitScalar(s, r).toPointBytes();
                        if (!Arrays.equals(viaBytes, viaScalar)) {
                            throw new FormsDisagree("commitBytes(B, " + r + ") differs from commitScalar(s, " + r + ")");
                        }
                    }
                }
                Map<String, String> out = new LinkedHashMap<>();
                out.put("b0Hex", HEX.formatHex(im[0]));
                out.put("b1Hex", HEX.formatHex(im[1]));
                out.put("b2Hex", HEX.formatHex(im[2]));
                out.put("uniformBytesHex", HEX.formatHex(im[3]));
                out.put("scalar", s.toString());
                yield object(out);
            }
            case "verifyOpening" -> {
                G1PedersenBytesCommitment c = codec.decodePoint(hex(in, "pointHex"));
                byte[] payload = payload(in.get("payload"));
                BigInteger r = integer(in, "blinding");
                // The array and every stream form must give the same verdict or the same class.
                Map<String, Supplier<String>> forms = new LinkedHashMap<>();
                forms.put("array", () -> String.valueOf(pedersen.verifyBytes(c, payload, r)));
                forms.put("declared(" + payload.length + ")", () -> io(() -> String.valueOf(
                        pedersen.verifyBytes(c, new ByteArrayInputStream(payload), payload.length, r))));
                forms.put("toEnd(" + payload.length + ")", () -> io(() -> String.valueOf(
                        pedersen.verifyBytesToEnd(c, new ByteArrayInputStream(payload), payload.length, r))));
                forms.put("toEnd(max)", () -> io(() -> String.valueOf(
                        pedersen.verifyBytesToEnd(c, new ByteArrayInputStream(payload), SPEC_MAX_PAYLOAD_BYTES, r))));
                yield result(agreeOn("verifyBytes", forms));
            }
            case "encodeOpening" -> object(Map.of("openingHex",
                    HEX.formatHex(G1PedersenBlinding.encode(integer(in, "blinding")))));
            case "decodeOpening" -> object(Map.of("blinding",
                    G1PedersenBlinding.decode(hex(in, "openingHex")).toString()));
            case "encodeEnvelope" -> envelope(codec.decodePoint(hex(in, "pointHex")));
            case "decodeEnvelope" -> point(CommitmentEnvelope.decode(hex(in, "envelopeHex"),
                    bytesCodec(text(in, "expectedProfileId"))));
            default -> throw new IllegalStateException(op);
        };
    }

    /**
     * The payload sources of {@code pedersen-bls12-381-g1-v1.md} §5.1 for one bytes {@code commit}
     * case. The form the case names runs first. When its bound is inside {@code [0, MAX_PAYLOAD_BYTES]}
     * (every case but a {@code LENGTH_OUT_OF_RANGE} one, by the streams rule), the array form, the
     * declared-length form with the payload length and the read-to-end form with the payload length and
     * with the maximum run as well, and all must agree. An out-of-range bound is only valid for its own
     * form, so then that form runs alone.
     */
    private static Map<String, Supplier<String>> commitForms(JsonNode in, G1Pedersen pedersen) {
        byte[] payload = payload(in.get("payload"));
        BigInteger r = integer(in, "blinding");
        Map<String, Supplier<String>> forms = new LinkedHashMap<>();
        boolean inRange = true;
        if (in.has("declaredLength")) {
            long length = Long.parseLong(text(in, "declaredLength"));
            inRange = inPayloadRange(length);
            forms.put("declared(" + length + ")", () -> io(() -> HEX.formatHex(
                    pedersen.commitBytes(new ByteArrayInputStream(payload), length, r).toPointBytes())));
        } else if (in.has("maxBytes")) {
            long max = Long.parseLong(text(in, "maxBytes"));
            inRange = inPayloadRange(max);
            forms.put("toEnd(" + max + ")", () -> io(() -> HEX.formatHex(
                    pedersen.commitBytesToEnd(new ByteArrayInputStream(payload), max, r).toPointBytes())));
        }
        if (inRange) {
            forms.putIfAbsent("array", () -> HEX.formatHex(pedersen.commitBytes(payload, r).toPointBytes()));
            forms.putIfAbsent("declared(" + payload.length + ")", () -> io(() -> HEX.formatHex(
                    pedersen.commitBytes(new ByteArrayInputStream(payload), payload.length, r).toPointBytes())));
            forms.putIfAbsent("toEnd(" + payload.length + ")", () -> io(() -> HEX.formatHex(
                    pedersen.commitBytesToEnd(new ByteArrayInputStream(payload), payload.length, r).toPointBytes())));
            forms.putIfAbsent("toEnd(" + SPEC_MAX_PAYLOAD_BYTES + ")", () -> io(() -> HEX.formatHex(
                    pedersen.commitBytesToEnd(new ByteArrayInputStream(payload), SPEC_MAX_PAYLOAD_BYTES, r)
                            .toPointBytes())));
        }
        return forms;
    }

    private static CommitmentCodec<G1PedersenCommitment> scalarCodec(String expectedProfileId) {
        // Validation pinned expectedProfileId to the file's own profile.
        if (!expectedProfileId.equals(SCALAR)) throw new IllegalStateException(expectedProfileId);
        return G1PedersenCommitment.CODEC;
    }

    private static CommitmentCodec<G1PedersenBytesCommitment> bytesCodec(String expectedProfileId) {
        if (!expectedProfileId.equals(BYTES)) throw new IllegalStateException(expectedProfileId);
        return G1PedersenBytesCommitment.CODEC;
    }

    // ---- field readers (spec §13.2; shapes already validated) ----

    /** The length of a validated payload, without materialising a pattern payload. */
    private static long payloadLength(JsonNode node) {
        return node.has("hex") ? node.get("hex").asText().length() / 2 : Integer.parseInt(node.get("length").asText());
    }

    /** A payload: {@code {"hex"}} or the pattern {@code octet i = (131·i + 17) mod 256}. */
    static byte[] payload(JsonNode node) {
        if (node.has("hex")) return HEX.parseHex(node.get("hex").asText());
        int length = Integer.parseInt(node.get("length").asText());
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) out[i] = (byte) ((131L * i + 17) % 256);
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

    /** §13.3 G1 {@code decodePoint}: the identity, or the 48-octet big-endian affine coordinates. */
    private static ObjectNode coordinates(G1Point p) {
        if (p.isInfinity()) return object(Map.of("identity", "true"));
        return object(Map.of("xHex", HEX.formatHex(i2osp(p.x().value(), COORDINATE_OCTETS)),
                "yHex", HEX.formatHex(i2osp(p.y().value(), COORDINATE_OCTETS))));
    }

    private static byte[] i2osp(BigInteger x, int octets) {
        if (x.signum() < 0 || x.bitLength() > 8 * octets) throw new IllegalStateException("I2OSP overflow");
        byte[] raw = x.toByteArray();
        byte[] out = new byte[octets];
        int skip = raw.length > octets ? raw.length - octets : 0;
        System.arraycopy(raw, skip, out, octets - (raw.length - skip), raw.length - skip);
        return out;
    }

    // ---- helpers ----

    /** A strictly decoded point and its commitment's public re-encoding ({@code toPointBytes}). */
    private record Decoded(G1Point point, byte[] encoding) {
    }

    private static Decoded decoded(G1PedersenCommitment c) {
        return new Decoded(c.point(), c.toPointBytes());
    }

    private static Decoded decoded(G1PedersenBytesCommitment c) {
        return new Decoded(c.point(), c.toPointBytes());
    }

    /** A disagreement between forms of one operation; always a case failure. */
    private static final class FormsDisagree extends RuntimeException {
        FormsDisagree(String message) {
            super(message);
        }
    }

    /**
     * Runs every strict decoder of a profile (spec §8: {@code decode} and {@code CODEC.decodePoint});
     * all must give the same point or the same class, and an accepted point must re-encode to exactly
     * the input (spec §4: the encoding is canonical).
     */
    private static G1Point agreeOnPoint(byte[] input, List<Supplier<Decoded>> decoders) {
        Map<String, Supplier<String>> forms = new LinkedHashMap<>();
        G1Point[] first = new G1Point[1];
        for (int i = 0; i < decoders.size(); i++) {
            Supplier<Decoded> d = decoders.get(i);
            forms.put("decoder " + i, () -> {
                Decoded p = d.get();
                if (first[0] == null) first[0] = p.point();
                if (!Arrays.equals(p.encoding(), input)) {
                    throw new FormsDisagree("accepted point does not re-encode to its input");
                }
                return HEX.formatHex(p.encoding());
            });
        }
        agreeOn("decodePoint", forms);
        return first[0];
    }

    /** All forms must return the same value or throw the same error class; returns or rethrows it. */
    private static String agreeOn(String what, Map<String, Supplier<String>> forms) {
        String outcome = null;
        String firstForm = null;
        CommitmentFormatException error = null;
        String value = null;
        for (Map.Entry<String, Supplier<String>> form : forms.entrySet()) {
            String o;
            try {
                String v = form.getValue().get();
                o = "value " + v;
                if (outcome == null) value = v;
            } catch (CommitmentFormatException e) {
                o = "class " + e.reason();
                if (outcome == null) error = e;
            }
            if (outcome == null) {
                outcome = o;
                firstForm = form.getKey();
            } else if (!outcome.equals(o)) {
                throw new FormsDisagree(what + ": " + firstForm + " gave " + outcome + " but " + form.getKey() + " gave " + o);
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
}
