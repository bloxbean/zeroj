package com.bloxbean.cardano.zeroj.api;

import org.junit.jupiter.api.Test;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.SpecificationVersion;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.math.BigDecimal;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticatedStateCircuitManifestTest {
    private static final String SHA = "00".repeat(32);
    private static final String POSEIDON =
            AuthenticatedStateCircuitManifest.POSEIDON_PARAMETER_FINGERPRINT;

    @Test
    void validatesTemplateSchemaAndArtifactIdentityTogether() {
        assertDoesNotThrow(() -> manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-jmt-v1-inclusion-s8-p1", 8, "c10-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s9-p1", 8, "c10-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p2", 8, "c10-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w20-p2"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s08-p1", 8, "c10-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p01", 8, "c10-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c01-w20-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w01-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w1-p1"));
        assertThrows(IllegalArgumentException.class,
                () -> manifest("zeroj-mpf-v1-inclusion-s8-p1", 8,
                        "c999999999999999999999-w20-p1"));
    }

    @Test
    void productionApprovalRequiresCeremonyTranscript() {
        assertThrows(IllegalArgumentException.class, () -> new AuthenticatedStateCircuitManifest.SetupProvenance(
                "benchmark-single-party", "local", null, true));
        assertThrows(IllegalArgumentException.class, () -> new AuthenticatedStateCircuitManifest.SetupProvenance(
                "multi-party-ceremony", "ceremony", null, true));
        assertThrows(IllegalArgumentException.class, () -> new AuthenticatedStateCircuitManifest.SetupProvenance(
                "multi-party-ceremony", "ceremony", SHA, true));
    }

    @Test
    void jsonModelRoundTripsWithSchemaNamesAndOperationSlug() throws Exception {
        var original = manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w20-p1");
        ObjectMapper json = new ObjectMapper();
        String encoded = json.writeValueAsString(original.toJsonModel());
        assertFalse(encoded.contains("INCLUSION"));
        var decodedModel = json.readValue(encoded, new TypeReference<java.util.Map<String, Object>>() {});
        assertEquals(original, AuthenticatedStateCircuitManifest.fromJsonModel(decodedModel));
    }

    @Test
    void emittedModelValidatesAgainstPublishedSchema() throws Exception {
        ObjectMapper json = new ObjectMapper();
        Path schemaPath = Path.of(System.getProperty("zeroj.manifest.schema"));
        try (InputStream input = Files.newInputStream(schemaPath)) {
            var schema = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)
                    .getSchema(input);
            var valid = (com.fasterxml.jackson.databind.node.ObjectNode) json.valueToTree(
                    manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w20-p1").toJsonModel());
            assertTrue(schema.validate(valid).isEmpty());

            var wrongParameters = valid.deepCopy();
            wrongParameters.put("poseidonParameterFingerprint", "11".repeat(32));
            assertFalse(schema.validate(wrongParameters).isEmpty());

            var prematureProduction = valid.deepCopy();
            ((com.fasterxml.jackson.databind.node.ObjectNode)
                    prematureProduction.path("setupProvenance")).put("productionApproved", true);
            assertFalse(schema.validate(prematureProduction).isEmpty());
        }
    }

    @Test
    void parserFailsClosedForUnknownMissingAndExplicitNullFields() {
        Map<String, Object> top = mutableModel();
        top.put("unknown", true);
        assertInvalid(top);

        top = mutableModel();
        top.put("maxSteps", new BigDecimal("8.0000000000000000000000000000000001"));
        assertInvalid(top);

        top = mutableModel();
        var fractionalInputs = new ArrayList<>(castList(top.get("publicInputs")));
        var fractionalInput = new LinkedHashMap<>(castMap(fractionalInputs.get(0)));
        fractionalInput.put("index", new BigDecimal("0.0000000000000000000000000000000001"));
        fractionalInputs.set(0, fractionalInput);
        top.put("publicInputs", fractionalInputs);
        assertInvalid(top);

        top = mutableModel();
        top.put("poseidonParameterFingerprint", "11".repeat(32));
        assertInvalid(top);

        assertThrows(IllegalArgumentException.class, () -> {
            ObjectMapper json = new ObjectMapper();
            Map<String, Object> parsed = json.readValue(
                    json.writeValueAsString(mutableModel()).replace(
                            "\"maxSteps\":8",
                            "\"maxSteps\":8.0000000000000000000000000000000001"),
                    new TypeReference<Map<String, Object>>() {});
            assertTrue(parsed.get("maxSteps") instanceof Double,
                    "regression must exercise Jackson's rounded Double boundary");
            AuthenticatedStateCircuitManifest.fromJsonModel(parsed);
        });

        top = mutableModel();
        top.remove("curve");
        assertInvalid(top);

        top = mutableModel();
        top.put("provingKeyFormat", null);
        assertInvalid(top);

        top = mutableModel();
        var inputs = new ArrayList<>(castList(top.get("publicInputs")));
        var input = new LinkedHashMap<>(castMap(inputs.get(0)));
        input.put("unknown", 1);
        inputs.set(0, input);
        top.put("publicInputs", inputs);
        assertInvalid(top);

        top = mutableModel();
        var setup = new LinkedHashMap<>(castMap(top.get("setupProvenance")));
        setup.put("transcriptSha256", null);
        top.put("setupProvenance", setup);
        assertInvalid(top);
    }

    @Test
    void operationSchemaBindsStructureCountAndExactPublicInputOrder() {
        assertDoesNotThrow(() -> transitionManifest(
                "zeroj-mpf-v1-value-update-s8-p2", "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.VALUE_UPDATE,
                List.of(input(0, "oldRoot"), input(1, "newRoot"))));
        assertThrows(IllegalArgumentException.class, () -> transitionManifest(
                "zeroj-mpf-v1-value-update-s8-p2", "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.VALUE_UPDATE,
                List.of(input(0, "newRoot"), input(1, "oldRoot"))));
        assertThrows(IllegalArgumentException.class, () -> transitionManifest(
                "zeroj-jmt-v1-delete-s8-p2", "zeroj-poseidon-jmt-v1",
                AuthenticatedStateCircuitManifest.Operation.DELETE,
                List.of(input(0, "oldRoot"), input(1, "newRoot"))));
        assertThrows(IllegalArgumentException.class, () -> transitionManifest(
                "zeroj-mpf-v1-tombstone-update-s8-p2", "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.TOMBSTONE_UPDATE,
                List.of(input(0, "oldRoot"), input(1, "newRoot"))));
        assertDoesNotThrow(() -> transitionManifest(
                "zeroj-jmt-v1-tombstone-update-s8-p3", "zeroj-poseidon-jmt-v1",
                AuthenticatedStateCircuitManifest.Operation.TOMBSTONE_UPDATE,
                List.of(input(0, "oldRoot"), input(1, "newRoot"),
                        input(2, "jmt_tombstone_value_hash"))));
        assertThrows(IllegalArgumentException.class, () -> transitionManifest(
                "zeroj-jmt-v1-tombstone-update-s8-p3", "zeroj-poseidon-jmt-v1",
                AuthenticatedStateCircuitManifest.Operation.TOMBSTONE_UPDATE,
                List.of(input(0, "oldRoot"), input(1, "newRoot"), input(2, "tombstone"))));
        assertThrows(IllegalArgumentException.class, () -> transitionManifest(
                "zeroj-jmt-v1-tombstone-update-s8-p2", "zeroj-poseidon-jmt-v1",
                AuthenticatedStateCircuitManifest.Operation.TOMBSTONE_UPDATE,
                List.of(input(0, "oldRoot"), input(1, "newRoot"))));
        assertDoesNotThrow(() -> transitionManifest(
                "zeroj-jmt-v1-insert-empty-s8-p2", "zeroj-poseidon-jmt-v1",
                AuthenticatedStateCircuitManifest.Operation.INSERT_EMPTY,
                List.of(input(0, "oldRoot"), input(1, "newRoot"))));
        assertDoesNotThrow(() -> transitionManifest(
                "zeroj-mpf-v1-insert-different-leaf-s8-p2", "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.INSERT_DIFFERENT_LEAF,
                List.of(input(0, "oldRoot"), input(1, "newRoot"))));
    }

    @Test
    void canonicalManifestBytesAndDigestDoNotDependOnMapOrdering() throws Exception {
        var value = manifest("zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w20-p1");
        String canonical = new String(value.canonicalJsonBytes(), StandardCharsets.UTF_8);
        assertTrue(canonical.startsWith(
                "{\"schemaVersion\":\"zeroj-circuit-manifest-v1\",\"templateId\":"));
        assertTrue(canonical.endsWith(
                "\"setupProvenance\":{\"kind\":\"benchmark-single-party\",\"setupId\":\"local-test\",\"productionApproved\":false}}"));
        assertEquals(64, value.canonicalSha256().length());

        var reordered = new LinkedHashMap<String, Object>();
        value.toJsonModel().entrySet().stream()
                .sorted(Map.Entry.<String, Object>comparingByKey().reversed())
                .forEach(entry -> reordered.put(entry.getKey(), entry.getValue()));
        var parsed = AuthenticatedStateCircuitManifest.fromJsonModel(reordered);
        assertEquals(value.canonicalSha256(), parsed.canonicalSha256());
        assertNotEquals(new ObjectMapper().writeValueAsString(reordered), canonical);
    }

    @Test
    void canonicalManifestHasLiteralCrossLanguageBytesAndDigestVector() {
        var value = new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                "zeroj-mpf-v1-inclusion-s8-p1",
                "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.INCLUSION,
                8,
                List.of(input(0, "root")),
                POSEIDON,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                "00".repeat(32),
                "c10-w20-p1",
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                "11".repeat(32),
                AuthenticatedStateCircuitManifest.PK_FORMAT,
                "22".repeat(32),
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "multi-party-ceremony", "ceremony\"\\\n" + (char) 1 + "☃",
                        "33".repeat(32), false));

        assertEquals("eyJzY2hlbWFWZXJzaW9uIjoiemVyb2otY2lyY3VpdC1tYW5pZmVzdC12MSIsInRlbXBsYXRlSWQiOiJ6ZXJvai1tcGYtdjEtaW5jbHVzaW9uLXM4LXAxIiwic3RydWN0dXJlUHJvZmlsZSI6Inplcm9qLXBvc2VpZG9uLW1wZi12MSIsIm9wZXJhdGlvbiI6ImluY2x1c2lvbiIsIm1heFN0ZXBzIjo4LCJwdWJsaWNJbnB1dHMiOlt7ImluZGV4IjowLCJuYW1lIjoicm9vdCIsInR5cGUiOiJmaWVsZCIsImVuY29kaW5nIjoiY2Fub25pY2FsLXVuc2lnbmVkLWJpZy1lbmRpYW4tMzIifV0sInBvc2VpZG9uUGFyYW1ldGVyRmluZ2VycHJpbnQiOiI0YmY0ODlmM2EyMzFjYmRiYTNlOWI4YzJkMjE5NjZlMDUyYmY5MTMyYjlkZGY2NTI5YWEzZjU2OTI5N2E4ZmMyIiwicjFjc0Zvcm1hdCI6Inplcm9qLXIxY3MtY2Fub25pY2FsLXYxIiwicjFjc1NoYTI1NiI6IjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJkaW1lbnNpb25GaW5nZXJwcmludCI6ImMxMC13MjAtcDEiLCJwcm92aW5nU3lzdGVtIjoiZ3JvdGgxNiIsImN1cnZlIjoiYmxzMTItMzgxIiwidmVyaWZpY2F0aW9uS2V5Rm9ybWF0IjoiemVyb2otZ3JvdGgxNi12ay1ibHMxMi0zODEtdjEiLCJ2ZXJpZmljYXRpb25LZXlTaGEyNTYiOiIxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExIiwicHJvdmluZ0tleUZvcm1hdCI6Inplcm9qLWdyb3RoMTYtcGstYmxzMTItMzgxLXYxIiwicHJvdmluZ0tleVNoYTI1NiI6IjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIiLCJzZXR1cFByb3ZlbmFuY2UiOnsia2luZCI6Im11bHRpLXBhcnR5LWNlcmVtb255Iiwic2V0dXBJZCI6ImNlcmVtb255XCJcXFx1MDAwYVx1MDAwMeKYgyIsInRyYW5zY3JpcHRTaGEyNTYiOiIzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzIiwicHJvZHVjdGlvbkFwcHJvdmVkIjpmYWxzZX19",
                Base64.getEncoder().encodeToString(value.canonicalJsonBytes()));
        assertEquals("ee8ea2bf894be5f6cfe0ec7b609cd441bb625bc4a0095095f5d01d828dd0025b", value.canonicalSha256());
    }

    private static AuthenticatedStateCircuitManifest manifest(
            String id, int maxSteps, String dimensions) {
        return new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                id,
                "zeroj-poseidon-mpf-v1",
                AuthenticatedStateCircuitManifest.Operation.INCLUSION,
                maxSteps,
                List.of(new AuthenticatedStateCircuitManifest.PublicInput(
                        0, "root", "field", "canonical-unsigned-big-endian-32")),
                POSEIDON,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                SHA,
                dimensions,
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                SHA,
                null,
                null,
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "benchmark-single-party", "local-test", null, false));
    }

    private static AuthenticatedStateCircuitManifest transitionManifest(
            String id,
            String profile,
            AuthenticatedStateCircuitManifest.Operation operation,
            List<AuthenticatedStateCircuitManifest.PublicInput> inputs) {
        return new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                id,
                profile,
                operation,
                8,
                inputs,
                POSEIDON,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                SHA,
                "c10-w20-p" + inputs.size(),
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                SHA,
                null,
                null,
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "benchmark-single-party", "local-test", null, false));
    }

    private static AuthenticatedStateCircuitManifest.PublicInput input(int index, String name) {
        return new AuthenticatedStateCircuitManifest.PublicInput(
                index, name, "field", "canonical-unsigned-big-endian-32");
    }

    private static Map<String, Object> mutableModel() {
        return new LinkedHashMap<>(manifest(
                "zeroj-mpf-v1-inclusion-s8-p1", 8, "c10-w20-p1").toJsonModel());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> castList(Object value) {
        return (List<Object>) value;
    }

    private static void assertInvalid(Map<String, Object> model) {
        assertThrows(IllegalArgumentException.class,
                () -> AuthenticatedStateCircuitManifest.fromJsonModel(model));
    }
}
