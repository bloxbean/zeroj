package com.bloxbean.cardano.zeroj.api;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * Semantically validated identity for one bounded MPF/JMT circuit and its
 * Groth16 artifacts. Dimension equality is metadata, never circuit identity.
 */
public record AuthenticatedStateCircuitManifest(
        String schemaVersion,
        String templateId,
        String structureProfile,
        Operation operation,
        int maxSteps,
        List<PublicInput> publicInputs,
        String poseidonParameterFingerprint,
        String r1csFormat,
        String r1csSha256,
        String dimensionFingerprint,
        String provingSystem,
        String curve,
        String verificationKeyFormat,
        String verificationKeySha256,
        String provingKeyFormat,
        String provingKeySha256,
        SetupProvenance setupProvenance) {

    public static final String SCHEMA_VERSION = "zeroj-circuit-manifest-v1";
    public static final String R1CS_FORMAT = "zeroj-r1cs-canonical-v1";
    public static final String VK_FORMAT = "zeroj-groth16-vk-bls12-381-v1";
    public static final String PK_FORMAT = "zeroj-groth16-pk-bls12-381-v1";
    public static final String POSEIDON_PARAMETER_FINGERPRINT =
            "4bf489f3a231cbdba3e9b8c2d21966e052bf9132b9ddf6529aa3f569297a8fc2";

    private static final Pattern TEMPLATE = Pattern.compile(
            "^zeroj-(mpf|jmt)-v1-([a-z0-9-]+)-s(0|[1-9][0-9]*)-p([1-9][0-9]*)$");
    private static final Pattern DIMENSIONS = Pattern.compile(
            "^c([1-9][0-9]*)-w([1-9][0-9]*)-p(0|[1-9][0-9]*)$");
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");

    public AuthenticatedStateCircuitManifest {
        requireEqual("schemaVersion", SCHEMA_VERSION, schemaVersion);
        requireText("templateId", templateId);
        requireText("structureProfile", structureProfile);
        Objects.requireNonNull(operation, "operation");
        if (maxSteps < 0 || maxSteps > 64) throw new IllegalArgumentException("maxSteps must be in [0, 64]");
        publicInputs = List.copyOf(Objects.requireNonNull(publicInputs, "publicInputs"));
        if (publicInputs.isEmpty()) throw new IllegalArgumentException("publicInputs must not be empty");
        validatePublicInputs(publicInputs);
        requireEqual("poseidonParameterFingerprint", POSEIDON_PARAMETER_FINGERPRINT,
                poseidonParameterFingerprint);
        requireEqual("r1csFormat", R1CS_FORMAT, r1csFormat);
        requireSha("r1csSha256", r1csSha256);
        requireText("dimensionFingerprint", dimensionFingerprint);
        requireEqual("provingSystem", "groth16", provingSystem);
        requireEqual("curve", "bls12-381", curve);
        requireEqual("verificationKeyFormat", VK_FORMAT, verificationKeyFormat);
        requireSha("verificationKeySha256", verificationKeySha256);
        if ((provingKeyFormat == null) != (provingKeySha256 == null)) {
            throw new IllegalArgumentException("proving key format and digest must either both exist or both be absent");
        }
        if (provingKeyFormat != null) {
            requireEqual("provingKeyFormat", PK_FORMAT, provingKeyFormat);
            requireSha("provingKeySha256", provingKeySha256);
        }
        Objects.requireNonNull(setupProvenance, "setupProvenance");
        validateSemanticIdentity(templateId, structureProfile, operation, maxSteps,
                publicInputs, dimensionFingerprint);
    }

    /** JSON-library-neutral model whose keys and enum values match the v1 schema exactly. */
    public Map<String, Object> toJsonModel() {
        Map<String, Object> model = new LinkedHashMap<>();
        model.put("schemaVersion", schemaVersion);
        model.put("templateId", templateId);
        model.put("structureProfile", structureProfile);
        model.put("operation", operation.slug());
        model.put("maxSteps", maxSteps);
        model.put("publicInputs", publicInputs.stream().map(input -> {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("index", input.index());
            item.put("name", input.name());
            item.put("type", input.type());
            item.put("encoding", input.encoding());
            return Map.copyOf(item);
        }).toList());
        model.put("poseidonParameterFingerprint", poseidonParameterFingerprint);
        model.put("r1csFormat", r1csFormat);
        model.put("r1csSha256", r1csSha256);
        model.put("dimensionFingerprint", dimensionFingerprint);
        model.put("provingSystem", provingSystem);
        model.put("curve", curve);
        model.put("verificationKeyFormat", verificationKeyFormat);
        model.put("verificationKeySha256", verificationKeySha256);
        if (provingKeyFormat != null) {
            model.put("provingKeyFormat", provingKeyFormat);
            model.put("provingKeySha256", provingKeySha256);
        }
        Map<String, Object> setup = new LinkedHashMap<>();
        setup.put("kind", setupProvenance.kind());
        setup.put("setupId", setupProvenance.setupId());
        if (setupProvenance.transcriptSha256() != null) {
            setup.put("transcriptSha256", setupProvenance.transcriptSha256());
        }
        setup.put("productionApproved", setupProvenance.productionApproved());
        model.put("setupProvenance", Map.copyOf(setup));
        return java.util.Collections.unmodifiableMap(model);
    }

    /**
     * Returns the unique UTF-8 JSON encoding defined by
     * {@code zeroj-circuit-manifest-json-v1}. Field order is fixed here rather
     * than inherited from a JSON library or map implementation.
     */
    public byte[] canonicalJsonBytes() {
        StringBuilder json = new StringBuilder(1536);
        json.append('{');
        appendStringProperty(json, "schemaVersion", schemaVersion, false);
        appendStringProperty(json, "templateId", templateId, true);
        appendStringProperty(json, "structureProfile", structureProfile, true);
        appendStringProperty(json, "operation", operation.slug(), true);
        appendNumberProperty(json, "maxSteps", maxSteps, true);
        json.append(",\"publicInputs\":[");
        for (int index = 0; index < publicInputs.size(); index++) {
            if (index > 0) json.append(',');
            PublicInput input = publicInputs.get(index);
            json.append('{');
            appendNumberProperty(json, "index", input.index(), false);
            appendStringProperty(json, "name", input.name(), true);
            appendStringProperty(json, "type", input.type(), true);
            appendStringProperty(json, "encoding", input.encoding(), true);
            json.append('}');
        }
        json.append(']');
        appendStringProperty(json, "poseidonParameterFingerprint", poseidonParameterFingerprint, true);
        appendStringProperty(json, "r1csFormat", r1csFormat, true);
        appendStringProperty(json, "r1csSha256", r1csSha256, true);
        appendStringProperty(json, "dimensionFingerprint", dimensionFingerprint, true);
        appendStringProperty(json, "provingSystem", provingSystem, true);
        appendStringProperty(json, "curve", curve, true);
        appendStringProperty(json, "verificationKeyFormat", verificationKeyFormat, true);
        appendStringProperty(json, "verificationKeySha256", verificationKeySha256, true);
        if (provingKeyFormat != null) {
            appendStringProperty(json, "provingKeyFormat", provingKeyFormat, true);
            appendStringProperty(json, "provingKeySha256", provingKeySha256, true);
        }
        json.append(",\"setupProvenance\":{");
        appendStringProperty(json, "kind", setupProvenance.kind(), false);
        appendStringProperty(json, "setupId", setupProvenance.setupId(), true);
        if (setupProvenance.transcriptSha256() != null) {
            appendStringProperty(json, "transcriptSha256", setupProvenance.transcriptSha256(), true);
        }
        json.append(",\"productionApproved\":").append(setupProvenance.productionApproved());
        json.append("}}");
        return json.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** SHA-256 identity of {@link #canonicalJsonBytes()}. */
    public String canonicalSha256() {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(canonicalJsonBytes()));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    /** Reconstructs and semantically validates a schema-shaped JSON object model. */
    public static AuthenticatedStateCircuitManifest fromJsonModel(Map<String, ?> model) {
        Objects.requireNonNull(model, "model");
        requireKeys(model, "manifest",
                java.util.Set.of(
                        "schemaVersion", "templateId", "structureProfile", "operation", "maxSteps",
                        "publicInputs", "poseidonParameterFingerprint", "r1csFormat", "r1csSha256",
                        "dimensionFingerprint", "provingSystem", "curve", "verificationKeyFormat",
                        "verificationKeySha256", "setupProvenance"),
                java.util.Set.of("provingKeyFormat", "provingKeySha256"));
        List<PublicInput> inputs = list(model, "publicInputs").stream().map(item -> {
            Map<String, ?> input = map(item, "publicInputs item");
            requireKeys(input, "publicInputs item",
                    java.util.Set.of("index", "name", "type", "encoding"), java.util.Set.of());
            return new PublicInput(integer(input, "index"), text(input, "name"),
                    text(input, "type"), text(input, "encoding"));
        }).toList();
        Map<String, ?> setup = map(model.get("setupProvenance"), "setupProvenance");
        requireKeys(setup, "setupProvenance",
                java.util.Set.of("kind", "setupId", "productionApproved"),
                java.util.Set.of("transcriptSha256"));
        return new AuthenticatedStateCircuitManifest(
                text(model, "schemaVersion"),
                text(model, "templateId"),
                text(model, "structureProfile"),
                Operation.fromSlug(text(model, "operation")),
                integer(model, "maxSteps"),
                inputs,
                text(model, "poseidonParameterFingerprint"),
                text(model, "r1csFormat"),
                text(model, "r1csSha256"),
                text(model, "dimensionFingerprint"),
                text(model, "provingSystem"),
                text(model, "curve"),
                text(model, "verificationKeyFormat"),
                text(model, "verificationKeySha256"),
                optionalText(model, "provingKeyFormat"),
                optionalText(model, "provingKeySha256"),
                new SetupProvenance(
                        text(setup, "kind"),
                        text(setup, "setupId"),
                        optionalText(setup, "transcriptSha256"),
                        bool(setup, "productionApproved")));
    }

    private static void validateSemanticIdentity(
            String templateId,
            String structureProfile,
            Operation operation,
            int maxSteps,
            List<PublicInput> publicInputs,
            String dimensionFingerprint) {
        Matcher template = TEMPLATE.matcher(templateId);
        if (!template.matches()) throw new IllegalArgumentException("invalid templateId: " + templateId);
        String expectedStructure = structureProfile.equals("zeroj-poseidon-mpf-v1") ? "mpf"
                : structureProfile.equals("zeroj-poseidon-jmt-v1") ? "jmt" : null;
        if (expectedStructure == null || !expectedStructure.equals(template.group(1))) {
            throw new IllegalArgumentException("template structure does not match structureProfile");
        }
        if (!operation.slug().equals(template.group(2))) {
            throw new IllegalArgumentException("template operation does not match operation");
        }
        if (parseCanonicalInt("template step bound", template.group(3)) != maxSteps) {
            throw new IllegalArgumentException("template step bound does not match maxSteps");
        }
        int publicCount = publicInputs.size();
        if (parseCanonicalInt("template public count", template.group(4)) != publicCount) {
            throw new IllegalArgumentException("template public count does not match publicInputs");
        }
        Matcher dimensions = DIMENSIONS.matcher(dimensionFingerprint);
        if (!dimensions.matches()) {
            throw new IllegalArgumentException("invalid canonical dimension fingerprint");
        }
        int constraints = parseCanonicalInt("dimension constraint count", dimensions.group(1));
        int wires = parseCanonicalInt("dimension wire count", dimensions.group(2));
        int dimensionPublic = parseCanonicalInt("dimension public count", dimensions.group(3));
        if (constraints < 1 || wires < 1 || dimensionPublic >= wires) {
            throw new IllegalArgumentException("invalid R1CS dimensions");
        }
        if (dimensionPublic != publicCount) {
            throw new IllegalArgumentException("dimension public count does not match publicInputs");
        }
        validateOperationSchema(expectedStructure, operation, publicInputs);
    }

    private static int parseCanonicalInt(String name, String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException(name + " exceeds the supported 32-bit range", invalid);
        }
    }

    private static void validatePublicInputs(List<PublicInput> inputs) {
        var names = new HashSet<String>();
        for (int index = 0; index < inputs.size(); index++) {
            PublicInput input = Objects.requireNonNull(inputs.get(index), "publicInputs[" + index + "]");
            if (input.index() != index) throw new IllegalArgumentException("public input indices must be contiguous");
            if (!names.add(input.name())) throw new IllegalArgumentException("duplicate public input name: " + input.name());
        }
    }

    private static void requireText(String name, String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
    }

    private static void requireEqual(String name, String expected, String actual) {
        if (!expected.equals(actual)) throw new IllegalArgumentException(name + " must be " + expected);
    }

    private static void requireSha(String name, String value) {
        if (value == null || !SHA256.matcher(value).matches()) {
            throw new IllegalArgumentException(name + " must be lowercase SHA-256 hex");
        }
    }

    private static String text(Map<String, ?> values, String name) {
        Object value = values.get(name);
        if (!(value instanceof String text)) throw new IllegalArgumentException(name + " must be a string");
        return text;
    }

    private static String optionalText(Map<String, ?> values, String name) {
        if (!values.containsKey(name)) return null;
        return text(values, name);
    }

    private static int integer(Map<String, ?> values, String name) {
        Object value = values.get(name);
        if (!(value instanceof Number number)) throw new IllegalArgumentException(name + " must be an integer");
        try {
            if (number instanceof BigInteger integer) return integer.intValueExact();
            if (number instanceof BigDecimal decimal) return decimal.intValueExact();
            if (number instanceof Byte || number instanceof Short || number instanceof Integer) {
                return number.intValue();
            }
            if (number instanceof Long integer) return Math.toIntExact(integer);
            // A JSON parser may round a non-integral decimal token to an
            // apparently integral IEEE-754 value before this semantic layer
            // sees it. Canonical manifests emit integer tokens, so floating
            // representations are rejected unconditionally.
            if (number instanceof Float || number instanceof Double) {
                throw new ArithmeticException("floating-point number is not a canonical integer token");
            }
        } catch (ArithmeticException invalid) {
            throw new IllegalArgumentException(name + " must be an exact 32-bit integer", invalid);
        }
        throw new IllegalArgumentException(name + " uses an unsupported numeric representation");
    }

    private static boolean bool(Map<String, ?> values, String name) {
        Object value = values.get(name);
        if (!(value instanceof Boolean bool)) throw new IllegalArgumentException(name + " must be boolean");
        return bool;
    }

    private static List<?> list(Map<String, ?> values, String name) {
        Object value = values.get(name);
        if (!(value instanceof List<?> list)) throw new IllegalArgumentException(name + " must be an array");
        return list;
    }

    private static Map<String, ?> map(Object value, String name) {
        if (!(value instanceof Map<?, ?> raw)) throw new IllegalArgumentException(name + " must be an object");
        Map<String, Object> output = new LinkedHashMap<>();
        raw.forEach((key, item) -> {
            if (!(key instanceof String text)) throw new IllegalArgumentException(name + " keys must be strings");
            output.put(text, item);
        });
        return output;
    }

    private static void requireKeys(
            Map<String, ?> values, String name, java.util.Set<String> required, java.util.Set<String> optional) {
        if (!values.keySet().containsAll(required)) {
            var missing = new java.util.HashSet<>(required);
            missing.removeAll(values.keySet());
            throw new IllegalArgumentException(name + " is missing keys " + missing);
        }
        var allowed = new java.util.HashSet<>(required);
        allowed.addAll(optional);
        var unknown = new java.util.HashSet<>(values.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) throw new IllegalArgumentException(name + " has unknown keys " + unknown);
    }

    private static void validateOperationSchema(
            String structure, Operation operation, List<PublicInput> publicInputs) {
        if (operation == Operation.DELETE && !"mpf".equals(structure)) {
            throw new IllegalArgumentException("physical delete is not a JMT v1 operation");
        }
        if (operation == Operation.TOMBSTONE_UPDATE && !"jmt".equals(structure)) {
            throw new IllegalArgumentException("tombstone update is not an MPF v1 operation");
        }
        boolean transition = operation == Operation.VALUE_UPDATE
                || operation == Operation.INSERT_EMPTY
                || operation == Operation.INSERT_DIFFERENT_LEAF
                || operation == Operation.DELETE
                || operation == Operation.TOMBSTONE_UPDATE;
        int expectedCount = operation == Operation.TOMBSTONE_UPDATE ? 3 : transition ? 2 : 1;
        int publicCount = publicInputs.size();
        if (publicCount != expectedCount) {
            throw new IllegalArgumentException(operation.slug() + " requires p" + expectedCount);
        }
        if (transition) {
            requireInputName(publicInputs, 0, "oldRoot");
            requireInputName(publicInputs, 1, "newRoot");
            if (operation == Operation.TOMBSTONE_UPDATE) {
                requireInputName(publicInputs, 2, "jmt_tombstone_value_hash");
            }
        } else {
            requireInputName(publicInputs, 0, "root");
        }
    }

    private static void requireInputName(List<PublicInput> publicInputs, int index, String expected) {
        String actual = publicInputs.get(index).name();
        if (!expected.equals(actual)) {
            throw new IllegalArgumentException(
                    "publicInputs[" + index + "].name must be " + expected + " for this operation");
        }
    }

    private static void appendStringProperty(
            StringBuilder output, String name, String value, boolean comma) {
        if (comma) output.append(',');
        appendJsonString(output, name);
        output.append(':');
        appendJsonString(output, value);
    }

    private static void appendNumberProperty(
            StringBuilder output, String name, int value, boolean comma) {
        if (comma) output.append(',');
        appendJsonString(output, name);
        output.append(':').append(value);
    }

    private static void appendJsonString(StringBuilder output, String value) {
        output.append('"');
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (Character.isHighSurrogate(ch)) {
                if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
                    throw new IllegalArgumentException("unpaired high surrogate in manifest string");
                }
                output.append(ch).append(value.charAt(++index));
            } else if (Character.isLowSurrogate(ch)) {
                throw new IllegalArgumentException("unpaired low surrogate in manifest string");
            } else if (ch == '"' || ch == '\\') {
                output.append('\\').append(ch);
            } else if (ch <= 0x1f) {
                output.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
            } else {
                output.append(ch);
            }
        }
        output.append('"');
    }

    public enum Operation {
        INCLUSION("inclusion"),
        NON_INCLUSION_EMPTY("non-inclusion-empty"),
        NON_INCLUSION_DIFFERENT_LEAF("non-inclusion-different-leaf"),
        VALUE_UPDATE("value-update"),
        INSERT_EMPTY("insert-empty"),
        INSERT_DIFFERENT_LEAF("insert-different-leaf"),
        DELETE("delete"),
        TOMBSTONE_UPDATE("tombstone-update");

        private final String slug;
        Operation(String slug) { this.slug = slug; }
        public String slug() { return slug; }

        public static Operation fromSlug(String slug) {
            for (Operation operation : values()) {
                if (operation.slug.equals(slug)) return operation;
            }
            throw new IllegalArgumentException("unsupported operation: " + slug);
        }
    }

    public record PublicInput(int index, String name, String type, String encoding) {
        public PublicInput {
            if (index < 0) throw new IllegalArgumentException("public input index must be non-negative");
            requireText("public input name", name);
            requireEqual("public input type", "field", type);
            requireEqual("public input encoding", "canonical-unsigned-big-endian-32", encoding);
        }
    }

    public record SetupProvenance(
            String kind,
            String setupId,
            String transcriptSha256,
            boolean productionApproved) {
        public SetupProvenance {
            if (!"benchmark-single-party".equals(kind) && !"multi-party-ceremony".equals(kind)) {
                throw new IllegalArgumentException("unsupported setup provenance kind");
            }
            requireText("setupId", setupId);
            if (transcriptSha256 != null) requireSha("transcriptSha256", transcriptSha256);
            if (productionApproved
                    && (!"multi-party-ceremony".equals(kind) || transcriptSha256 == null)) {
                throw new IllegalArgumentException(
                        "production approval requires a multi-party ceremony transcript digest");
            }
            if (productionApproved) {
                throw new IllegalArgumentException(
                        "productionApproved remains disabled until an externally reviewed release "
                                + "policy and exact-circuit ceremony are accepted");
            }
        }
    }
}
