package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.testkit.ContractTest;
import com.bloxbean.cardano.julc.testkit.TestDataBuilder;
import com.bloxbean.cardano.zeroj.api.AuthenticatedStateCircuitManifest;
import com.bloxbean.cardano.zeroj.api.Groth16ArtifactBundleIdentity;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16VerificationKeyCodec;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Shared integrity, identity, positive, and mutation gates for MPF/JMT proof bundles. */
abstract class PoseidonCardanoArtifactTestSupport extends ContractTest {
    private static final long MAX_JSON_BYTES = 65_536L;
    private static final long MAX_VERIFICATION_KEY_BYTES = 4_096L;
    private static final BigInteger FR = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder()
                    .maxDocumentLength(MAX_JSON_BYTES)
                    .maxNestingDepth(24)
                    .maxStringLength(4_096)
                    .maxNumberLength(128)
                    .build())
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build());

    protected final void verifyArtifact(
            String property,
            String label,
            String expectedProfile,
            Set<String> expectedTemplateIds) throws Exception {
        String configured = System.getProperty(property);
        assumeTrue(configured != null && !configured.isBlank(),
                "set -D" + property + "=PATH to run the artifact bridge");
        assertFalse(expectedTemplateIds.isEmpty(), "expected template set must not be empty");
        String[] bundles = configured.split(Pattern.quote(File.pathSeparator), -1);
        assertTrue(bundles.length > 0, "at least one artifact bundle is required");
        Set<Path> canonicalDirectories = new LinkedHashSet<>();
        Set<String> actualTemplateIds = new LinkedHashSet<>();
        for (int index = 0; index < bundles.length; index++) {
            assertFalse(bundles[index].isBlank(), "artifact bundle paths must not be blank");
            Path configuredDirectory = Path.of(bundles[index]).toAbsolutePath().normalize();
            assertTrue(Files.isDirectory(configuredDirectory),
                    "artifact bundle must be a directory");
            assertFalse(Files.isSymbolicLink(configuredDirectory),
                    "artifact bundle directory must not be a symlink");
            Path canonicalDirectory = configuredDirectory.toRealPath();
            assertEquals(configuredDirectory, canonicalDirectory,
                    "artifact bundle path must not contain symlink components");
            assertTrue(canonicalDirectories.add(canonicalDirectory),
                    "artifact bundle paths must be unique");
            String bundleLabel = bundles.length == 1 ? label : label + "-bundle-" + (index + 1);
            String templateId = verifyArtifactDirectory(
                    canonicalDirectory, bundleLabel, expectedProfile);
            assertTrue(expectedTemplateIds.contains(templateId),
                    "unexpected authenticated-state template: " + templateId);
            assertTrue(actualTemplateIds.add(templateId),
                    "artifact template IDs must be unique");
        }
        if (bundles.length > 1) {
            assertEquals(expectedTemplateIds, Set.copyOf(actualTemplateIds),
                    "multi-bundle release gate must contain the complete expected template set");
        }
    }

    private String verifyArtifactDirectory(
            Path configuredPath, String label, String expectedProfile) throws Exception {
        Path configuredDirectory = configuredPath.toAbsolutePath().normalize();
        assertTrue(Files.isDirectory(configuredDirectory), "artifact bundle must be a directory");
        assertFalse(Files.isSymbolicLink(configuredDirectory),
                "artifact bundle directory must not be a symlink");
        Path directory = configuredDirectory.toRealPath();
        assertEquals(configuredDirectory, directory,
                "artifact bundle path must not contain symlink components");
        Path manifestFile = resolveContained(directory, "manifest.json");
        assertTrue(Files.isRegularFile(manifestFile), "artifact bundle manifest must be a file");
        assertFalse(Files.isSymbolicLink(manifestFile), "artifact bundle manifest must not be a symlink");
        JsonNode bundleManifest = JSON.readTree(readBounded(manifestFile, MAX_JSON_BYTES));
        requireObject(bundleManifest, "outer manifest");
        assertEquals(Set.of(
                        "schema", "bundleIdentity", "profileId", "operation", "templateId",
                        "exactCircuitFingerprint", "r1csSha256", "circuitManifestSha256",
                        "verificationKeySha256", "bundleSha256", "publicInputs",
                        "publicInputFiles", "setupProvenance", "productionApproved",
                        "generatedAt", "files"),
                fieldNames(bundleManifest), "outer manifest schema must be exact");
        assertEquals("zeroj-cardano-groth16-artifacts-v2", text(bundleManifest, "schema"));
        assertEquals(Groth16ArtifactBundleIdentity.SCHEMA,
                text(bundleManifest, "bundleIdentity"));
        assertEquals(expectedProfile, text(bundleManifest, "profileId"));
        assertFalse(bool(bundleManifest, "productionApproved"));
        Instant.parse(text(bundleManifest, "generatedAt"));
        List<String> publicInputNames = textArray(
                array(bundleManifest, "publicInputs"), "publicInputs");
        assertTrue(!publicInputNames.isEmpty() && publicInputNames.size() <= 3,
                "artifact bundles support one to three public inputs");
        List<String> publicInputFiles = textArray(
                array(bundleManifest, "publicInputFiles"), "publicInputFiles");
        assertEquals(publicInputNames.size(), publicInputFiles.size());
        assertEquals(publicInputFiles.size(), new HashSet<>(publicInputFiles).size(),
                "public input files must be unique");
        for (int index = 0; index < publicInputFiles.size(); index++) {
            assertEquals("public-input-" + publicInputNames.get(index) + ".bin",
                    publicInputFiles.get(index),
                    "public input filename/order must be canonical");
        }
        Set<String> expectedFiles = expectedArtifactFiles(publicInputFiles);
        JsonNode declaredFiles = object(bundleManifest, "files");
        assertEquals(expectedFiles, fieldNames(declaredFiles),
                "file hash manifest must contain exactly the identity-bearing artifact files");
        Map<String, byte[]> verifiedFiles = verifyEveryFile(directory, declaredFiles);

        byte[] canonicalManifestBytes = verifiedFiles.get("circuit-manifest.json");
        Map<String, Object> model = JSON.readValue(
                canonicalManifestBytes, new TypeReference<>() {});
        var circuitManifest = AuthenticatedStateCircuitManifest.fromJsonModel(model);
        label = label + "-" + circuitManifest.templateId();
        assertArrayEquals(canonicalManifestBytes, circuitManifest.canonicalJsonBytes());
        assertEquals(expectedProfile, circuitManifest.structureProfile());
        assertFalse(circuitManifest.setupProvenance().productionApproved());
        assertEquals(sha256(canonicalManifestBytes),
                text(bundleManifest, "circuitManifestSha256"));
        assertEquals(circuitManifest.templateId(), text(bundleManifest, "templateId"));
        assertEquals(circuitManifest.operation().slug(), text(bundleManifest, "operation"));
        assertEquals(circuitManifest.r1csSha256(), text(bundleManifest, "r1csSha256"));
        assertEquals(
                JSON.valueToTree(circuitManifest.toJsonModel().get("setupProvenance")),
                object(bundleManifest, "setupProvenance"),
                "outer setup provenance must exactly duplicate the canonical circuit manifest");
        String exactFingerprint = circuitManifest.dimensionFingerprint()
                + "-r" + circuitManifest.r1csSha256();
        assertEquals(exactFingerprint,
                text(bundleManifest, "exactCircuitFingerprint"));
        List<String> manifestPublicInputNames = new ArrayList<>();
        circuitManifest.publicInputs().forEach(input -> manifestPublicInputNames.add(input.name()));
        assertEquals(publicInputNames, manifestPublicInputNames);

        byte[] verificationKeyBytes = verifiedFiles.get("verification-key.bin");
        String verificationKeySha256 = sha256(verificationKeyBytes);
        assertEquals(verificationKeySha256, circuitManifest.verificationKeySha256());
        assertEquals(verificationKeySha256,
                text(bundleManifest, "verificationKeySha256"));
        var verificationKey = Groth16VerificationKeyCodec.decode(verificationKeyBytes);
        assertArrayEquals(verificationKey.alpha(), artifact(verifiedFiles, "vk-alpha.g1", 48));
        assertArrayEquals(verificationKey.beta(), artifact(verifiedFiles, "vk-beta.g2", 96));
        assertArrayEquals(verificationKey.gamma(), artifact(verifiedFiles, "vk-gamma.g2", 96));
        assertArrayEquals(verificationKey.delta(), artifact(verifiedFiles, "vk-delta.g2", 96));
        assertEquals(circuitManifest.publicInputs().size() + 1, verificationKey.ic().size(),
                "VK IC count must be public input arity + 1");
        for (int index = 0; index < verificationKey.ic().size(); index++) {
            assertArrayEquals(verificationKey.ic().get(index),
                    artifact(verifiedFiles, "vk-ic-" + index + ".g1", 48));
        }

        byte[] proofA = artifact(verifiedFiles, "proof-a.g1", 48);
        byte[] proofB = artifact(verifiedFiles, "proof-b.g2", 96);
        byte[] proofC = artifact(verifiedFiles, "proof-c.g1", 48);
        assertEquals(circuitManifest.publicInputs().size(), publicInputFiles.size());
        List<byte[]> encodedPublicInputs = new ArrayList<>();
        List<BigInteger> publicInputValues = new ArrayList<>();
        for (int index = 0; index < publicInputFiles.size(); index++) {
            String file = publicInputFiles.get(index);
            byte[] encoded = artifact(verifiedFiles, file, 32);
            BigInteger value = new BigInteger(1, encoded);
            assertTrue(value.compareTo(FR) < 0, "public input must be a canonical BLS12-381 scalar");
            encodedPublicInputs.add(encoded);
            publicInputValues.add(value);
        }
        String bundleSha256 = Groth16ArtifactBundleIdentity.sha256(
                circuitManifest, verificationKeyBytes, proofA, proofB, proofC,
                encodedPublicInputs);
        assertEquals(bundleSha256, text(bundleManifest, "bundleSha256"));
        assertEquals("bundle-" + bundleSha256, directory.getFileName().toString());
        assertEquals("vk-" + verificationKeySha256, directory.getParent().getFileName().toString());
        assertEquals(exactFingerprint,
                directory.getParent().getParent().getFileName().toString());
        assertEquals(circuitManifest.templateId(),
                directory.getParent().getParent().getParent().getFileName().toString());

        assertEquals(expectedFiles, verifiedFiles.keySet(),
                "file hash manifest must contain exactly the identity-bearing artifact files");

        List<PlutusData> ic = new ArrayList<>();
        for (byte[] point : verificationKey.ic()) ic.add(PlutusData.bytes(point));
        var program = compileValidator(Groth16BLS12381Verifier.class).program().applyParams(
                PlutusData.bytes(verificationKey.alpha()),
                PlutusData.bytes(verificationKey.beta()),
                PlutusData.bytes(verificationKey.gamma()),
                PlutusData.bytes(verificationKey.delta()),
                PlutusData.list(ic.toArray(PlutusData[]::new)));

        PlutusData[] publicInputData = publicInputValues.stream()
                .map(PlutusData::integer)
                .toArray(PlutusData[]::new);
        var redeemer = PlutusData.constr(0,
                PlutusData.bytes(proofA), PlutusData.bytes(proofB), PlutusData.bytes(proofC));
        var txOutRef = TestDataBuilder.randomTxOutRef_typed();
        var positiveContext = spendingContext(txOutRef, PlutusData.list(publicInputData))
                .redeemer(redeemer).buildPlutusData();
        long positiveStarted = System.nanoTime();
        var positive = evaluate(program, positiveContext);
        double positiveMillis = elapsedMillis(positiveStarted);
        assertSuccess(positive);

        long warmStarted = System.nanoTime();
        var warm = evaluate(program, positiveContext);
        double warmMillis = elapsedMillis(warmStarted);
        assertSuccess(warm);

        PlutusData[] mutatedInputData = publicInputData.clone();
        mutatedInputData[0] = PlutusData.integer(
                publicInputValues.get(0).add(BigInteger.ONE).mod(FR));
        var negativeContext = spendingContext(
                txOutRef, PlutusData.list(mutatedInputData))
                .redeemer(redeemer).buildPlutusData();
        long negativeStarted = System.nanoTime();
        var negative = evaluate(program, negativeContext);
        double negativeMillis = elapsedMillis(negativeStarted);
        assertFailure(negative);

        System.out.println("[" + label + "] exact manifest-bound proof Julc VM budget: "
                + positive.budgetConsumed());
        System.out.printf("[%s] Julc VM positive verify cold %.3f ms, warm %.3f ms, "
                        + "mutated-root rejection %.3f ms%n",
                label, positiveMillis, warmMillis, negativeMillis);
        return circuitManifest.templateId();
    }

    private static Map<String, byte[]> verifyEveryFile(Path directory, JsonNode files) throws Exception {
        requireObject(files, "files");
        Set<String> names = new LinkedHashSet<>();
        Map<String, byte[]> values = new java.util.LinkedHashMap<>();
        var entries = files.fields();
        while (entries.hasNext()) {
            var entry = entries.next();
            String name = entry.getKey();
            assertTrue(names.add(name), "duplicate file name");
            JsonNode descriptor = entry.getValue();
            requireObject(descriptor, "files." + name);
            assertEquals(Set.of("bytes", "sha256"), fieldNames(descriptor),
                    "file descriptor schema must be exact");
            Path file = resolveContained(directory, name);
            assertTrue(Files.isRegularFile(file), "artifact must be a regular file: " + name);
            assertFalse(Files.isSymbolicLink(file), "artifact must not be a symlink: " + name);
            long maximum = maximumArtifactBytes(name);
            long declaredBytes = nonNegativeLong(descriptor, "bytes");
            assertTrue(declaredBytes <= maximum, "artifact exceeds its size bound: " + name);
            byte[] value = readBounded(file, maximum);
            assertEquals(declaredBytes, value.length);
            String digest = text(descriptor, "sha256");
            assertTrue(SHA256.matcher(digest).matches(), "invalid file SHA-256: " + name);
            assertEquals(sha256(value), digest);
            values.put(name, value);
        }
        return java.util.Collections.unmodifiableMap(values);
    }

    private static Set<String> expectedArtifactFiles(List<String> publicInputFiles) {
        Set<String> expected = new LinkedHashSet<>(Set.of(
                "proof-a.g1", "proof-b.g2", "proof-c.g1",
                "vk-alpha.g1", "vk-beta.g2", "vk-gamma.g2", "vk-delta.g2",
                "verification-key.bin", "circuit-manifest.json"));
        for (int index = 0; index <= publicInputFiles.size(); index++) {
            expected.add("vk-ic-" + index + ".g1");
        }
        expected.addAll(publicInputFiles);
        return Set.copyOf(expected);
    }

    private static long maximumArtifactBytes(String name) {
        if (name.equals("circuit-manifest.json")) return MAX_JSON_BYTES;
        if (name.equals("verification-key.bin")) return MAX_VERIFICATION_KEY_BYTES;
        if (name.equals("proof-a.g1") || name.equals("proof-c.g1")
                || name.equals("vk-alpha.g1") || name.matches("vk-ic-[0-3]\\.g1")) return 48L;
        if (name.equals("proof-b.g2") || name.equals("vk-beta.g2")
                || name.equals("vk-gamma.g2") || name.equals("vk-delta.g2")) return 96L;
        if (name.matches("public-input-[A-Za-z0-9_-]+\\.bin")) return 32L;
        throw new IllegalArgumentException("unsupported artifact filename: " + name);
    }

    private static byte[] artifact(Map<String, byte[]> files, String name, int expectedBytes) {
        byte[] value = files.get(name);
        assertTrue(value != null, "missing verified artifact: " + name);
        assertEquals(expectedBytes, value.length, "unexpected artifact length: " + name);
        return value;
    }

    private static byte[] readBounded(Path file, long maximumBytes) throws Exception {
        Set<OpenOption> options = Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
        try (FileChannel channel = FileChannel.open(file, options)) {
            long size = channel.size();
            assertTrue(size >= 0 && size <= maximumBytes,
                    "artifact exceeds its size bound: " + file.getFileName());
            ByteBuffer output = ByteBuffer.allocate(Math.toIntExact(size));
            while (output.hasRemaining()) {
                assertTrue(channel.read(output) >= 0,
                        "artifact was truncated while reading: " + file.getFileName());
            }
            assertEquals(size, channel.size(),
                    "artifact changed size while reading: " + file.getFileName());
            return output.array();
        }
    }

    private static Set<String> fieldNames(JsonNode object) {
        requireObject(object, "object");
        Set<String> result = new HashSet<>();
        object.fieldNames().forEachRemaining(result::add);
        return result;
    }

    private static List<String> textArray(JsonNode array, String name) {
        assertTrue(array.isArray(), name + " must be an array");
        List<String> result = new ArrayList<>();
        for (JsonNode value : array) {
            assertTrue(value.isTextual(), name + " items must be strings");
            assertFalse(value.textValue().isBlank(), name + " items must not be blank");
            result.add(value.textValue());
        }
        return List.copyOf(result);
    }

    private static JsonNode object(JsonNode parent, String name) {
        JsonNode value = required(parent, name);
        requireObject(value, name);
        return value;
    }

    private static JsonNode array(JsonNode parent, String name) {
        JsonNode value = required(parent, name);
        assertTrue(value.isArray(), name + " must be an array");
        return value;
    }

    private static String text(JsonNode parent, String name) {
        JsonNode value = required(parent, name);
        assertTrue(value.isTextual(), name + " must be a string");
        assertFalse(value.textValue().isBlank(), name + " must not be blank");
        return value.textValue();
    }

    private static boolean bool(JsonNode parent, String name) {
        JsonNode value = required(parent, name);
        assertTrue(value.isBoolean(), name + " must be boolean");
        return value.booleanValue();
    }

    private static long nonNegativeLong(JsonNode parent, String name) {
        JsonNode value = required(parent, name);
        assertTrue(value.isIntegralNumber() && value.canConvertToLong(),
                name + " must be an exact 64-bit integer");
        long result = value.longValue();
        assertTrue(result >= 0, name + " must be non-negative");
        return result;
    }

    private static JsonNode required(JsonNode parent, String name) {
        JsonNode value = parent.get(name);
        assertTrue(value != null && !value.isNull(), name + " must exist and must not be null");
        return value;
    }

    private static void requireObject(JsonNode value, String name) {
        assertTrue(value != null && value.isObject(), name + " must be an object");
    }

    private static Path resolveContained(Path directory, String name) {
        Path relative = Path.of(name);
        assertFalse(relative.isAbsolute(), "artifact filename must be relative");
        assertEquals(1, relative.getNameCount(), "nested artifact paths are not allowed");
        assertEquals(relative.getFileName().toString(), name,
                "artifact filename must use one canonical path component");
        Path resolved = directory.resolve(relative).normalize();
        assertTrue(resolved.startsWith(directory), "artifact path escapes bundle directory");
        return resolved;
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static double elapsedMillis(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000.0;
    }
}
