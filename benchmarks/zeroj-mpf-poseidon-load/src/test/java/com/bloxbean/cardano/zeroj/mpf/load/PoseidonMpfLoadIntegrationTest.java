package com.bloxbean.cardano.zeroj.mpf.load;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonMpfLoadIntegrationTest {

    @Test
    void pre5ReleaseReopensTheSourceIdenticalDev1StoreButNoOtherCclVersion(
            @TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 20, 10, 4, 8, "none", false);
        var loaded = new PoseidonMpfLoadRunner(options).run();
        RunFiles files = new RunFiles(directory);
        RunFiles.Manifest current = files.readManifestUnchecked();
        RunFiles.Manifest dev1 = new RunFiles.Manifest(
                current.profileId(), "0.8.0-pre5-dev1", current.poseidonFingerprint(),
                current.datasetSchema(), current.seed(), current.targetEntries(),
                current.batchSize(), current.keyBytes(), current.valueBytes(),
                current.completedEntries(), current.rootHex(), current.status(),
                current.createdAt(), current.updatedAt());
        files.writeManifest(dev1);

        assertEquals(loaded.rootHex(), new PoseidonMpfLoadRunner(options).run().rootHex());
        assertEquals(4, new PoseidonMpfProofRunner(options).run().artifacts().size());

        RunFiles.Manifest unqualified = new RunFiles.Manifest(
                current.profileId(), "0.8.0-pre5-dev2", current.poseidonFingerprint(),
                current.datasetSchema(), current.seed(), current.targetEntries(),
                current.batchSize(), current.keyBytes(), current.valueBytes(),
                current.completedEntries(), current.rootHex(), current.status(),
                current.createdAt(), current.updatedAt());
        files.writeManifest(unqualified);
        IllegalStateException rejected = assertThrows(
                IllegalStateException.class, () -> new PoseidonMpfLoadRunner(options).run());
        assertTrue(rejected.getMessage().contains("verified-structures-compatible baseline"));
    }

    @Test
    void deterministicRocksDbLoadResumesAndRealProofsVerify(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 100, 17, 8, 8, "none", false);

        IllegalStateException interruption = assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfLoadRunner(options, (completed, root) -> {
                    if (completed == 34) throw new IllegalStateException("injected interruption");
                }).run());
        assertEquals("injected interruption", interruption.getMessage());

        var resumed = new PoseidonMpfLoadRunner(options).run();
        var reopened = new PoseidonMpfLoadRunner(options).run();

        assertEquals(100, resumed.entries());
        assertEquals(34, resumed.resumedFrom());
        assertEquals(100, reopened.resumedFrom());
        assertEquals(0, reopened.checkpointsWritten());
        assertEquals(resumed.rootHex(), reopened.rootHex());
        assertEquals("04cca47225056a86865086a40252278686c71c1fda50382f256f3b8a0e2bff8f",
                resumed.rootHex(), "ADR-0041 deterministic 100-entry golden root");
        assertTrue(resumed.databaseBytesAfter() > 0);
        assertTrue(resumed.pairCache().hits() > 0);
        assertTrue(resumed.walEnabled());
        assertTrue(resumed.syncWrites());
        assertTrue(resumed.productionDurabilityOptions());
        assertTrue(resumed.peakObservedRssBytes() > 0 || "unsupported".equals(resumed.rssSource()));

        var proofs = new PoseidonMpfProofRunner(options).run();
        assertEquals(8, proofs.artifacts().size());
        assertTrue(proofs.artifacts().stream().allMatch(proof -> proof.steps() <= options.maxSteps()));
        assertTrue(proofs.result().samples().stream().allMatch(sample -> sample.proofBytes() > 0));
        assertArrayEquals(java.util.HexFormat.of().parseHex(resumed.rootHex()), proofs.root());

        assertTrue(Files.isRegularFile(directory.resolve("manifest.json")));
        assertTrue(Files.isRegularFile(directory.resolve("report.json")));
    }

    @Test
    void resumeRefusesToAdoptMpfStateAheadOfAuthenticatedManifest(@TempDir Path directory)
            throws Exception {
        LoadOptions options = options(directory, 100, 20, 4, 8, "none", false);
        assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfLoadRunner(options, (completed, root) -> {
                    if (completed == 40) throw new IllegalStateException("stop-at-40");
                }).run());
        RunFiles files = new RunFiles(directory);
        byte[] checkpointAt40 = Files.readAllBytes(files.manifestFile());

        assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfLoadRunner(options, (completed, root) -> {
                    if (completed == 60) throw new IllegalStateException("stop-at-60");
                }).run());
        files.restoreManifest(checkpointAt40);

        IllegalStateException rejected = assertThrows(
                IllegalStateException.class, () -> new PoseidonMpfLoadRunner(options).run());
        assertTrue(rejected.getMessage().contains("refusing to adopt unverified commits"));
        assertEquals(40, files.readManifestUnchecked().completedEntries());
    }

    @Test
    void explicitLegacyProfileMigrationBacksUpAndVerifiesBeforeAndAfter(@TempDir Path directory)
            throws Exception {
        LoadOptions options = options(directory, 100, 20, 8, 8, "none", false);
        var load = new PoseidonMpfLoadRunner(options).run();
        RunFiles files = new RunFiles(directory);
        RunFiles.Manifest current = files.readManifestUnchecked();
        RunFiles.Manifest legacy = new RunFiles.Manifest(
                PoseidonMpfManifestMigration.LEGACY_PROFILE,
                PoseidonMpfManifestMigration.LEGACY_CCL,
                BuildInfo.legacyPoseidonFingerprint(),
                current.datasetSchema(), current.seed(), current.targetEntries(),
                current.batchSize(), current.keyBytes(), current.valueBytes(),
                current.completedEntries(), current.rootHex(), current.status(),
                current.createdAt(), current.updatedAt());
        files.writeManifest(legacy);

        assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfProofRunner(options).run(),
                "normal opens must reject the unreleased v2 alias");

        var result = new PoseidonMpfManifestMigration(options).run();
        assertEquals("migrated", result.status());
        assertEquals(load.rootHex(), result.rootHex());
        assertTrue(result.rootUnchanged());
        assertTrue(result.proofsUnchanged());
        assertEquals(8, result.samples());
        assertTrue(result.preMigrationVerificationNanos() > 0);
        assertTrue(result.postMigrationVerificationNanos() > 0);
        assertTrue(Files.isRegularFile(files.migrationBackupFile()));

        RunFiles.Manifest migrated = files.readManifestUnchecked();
        assertEquals("zeroj-poseidon-mpf-v1", migrated.profileId());
        assertEquals("0.8.0-pre5", migrated.cclVersion());
        assertEquals(BuildInfo.poseidonFingerprint(), migrated.poseidonFingerprint());
        assertEquals(load.rootHex(), migrated.rootHex());
        assertEquals(legacy, new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                files.migrationBackupFile().toFile(), RunFiles.Manifest.class));

        assertEquals("already-migrated", new PoseidonMpfManifestMigration(options).run().status());
        assertEquals(8, new PoseidonMpfProofRunner(options).run().artifacts().size());
    }

    @Test
    void oneEntryCircuitGeneratesAndIndependentlyVerifiesGroth16Proof(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 1, 1, 1, 0, "in-memory", true);
        new PoseidonMpfLoadRunner(options).run();
        var proofs = new PoseidonMpfProofRunner(options).run();

        var result = new PoseidonMpfCircuitBenchmark(options).run(proofs);

        assertEquals(0, result.observedProofSteps());
        assertTrue(result.constraints() > 0);
        assertEquals(1, result.publicInputs());
        assertEquals(Boolean.TRUE, result.positiveVerified());
        assertEquals(Boolean.TRUE, result.negativeInputRejected());
        assertEquals(192, result.compressedProofBytes());
        assertEquals(432, result.cardanoVerificationKeyBytes());
        Path artifacts = Path.of(result.cardanoArtifactsDirectory());
        assertTrue(artifacts.startsWith(directory.resolve("cardano-artifacts")
                .resolve(result.templateId()).resolve(result.fingerprint())));
        assertArtifactManifest(artifacts, result.templateId(), result.fingerprint());

        LoadOptions secondOptions = options(directory, 1, 1, 1, 1, "in-memory", true);
        var secondProofs = new PoseidonMpfProofRunner(secondOptions).run();
        var second = new PoseidonMpfCircuitBenchmark(secondOptions).run(secondProofs);
        assertNotEquals(result.cardanoArtifactsDirectory(), second.cardanoArtifactsDirectory());
        assertArtifactManifest(Path.of(second.cardanoArtifactsDirectory()),
                second.templateId(), second.fingerprint());
        assertTrue(Files.isRegularFile(artifacts.resolve("proof-a.g1")),
                "a second template must not overwrite the first template's artifacts");
    }

    @Test
    void proofDistributionIsReportedBeforeCircuitBoundIsEnforced(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 3, 3, 3, 0, "none", false);
        new PoseidonMpfLoadRunner(options).run();

        var proofs = new PoseidonMpfProofRunner(options).run();

        assertTrue(proofs.artifacts().stream().anyMatch(proof -> proof.steps() > options.maxSteps()));
        IllegalStateException error = assertThrows(IllegalStateException.class,
                () -> new PoseidonMpfCircuitBenchmark(options).run(proofs));
        assertTrue(error.getMessage().contains("exceeding MAX_STEPS=0"));
    }

    @Test
    void deterministicDatasetHasUniqueKeysAndExercisesRawValueFallback() {
        byte[][] keys = new byte[1_000][];
        for (int i = 0; i < keys.length; i++) {
            keys[i] = DeterministicDataset.key(25L, i);
            assertEquals(DeterministicDataset.KEY_BYTES, keys[i].length);
            byte[] value = DeterministicDataset.value(25L, i);
            assertEquals(DeterministicDataset.VALUE_BYTES, value.length);
            assertEquals(0xff, value[0] & 0xff);
        }
        for (int i = 1; i < keys.length; i++) assertFalse(Arrays.equals(keys[i - 1], keys[i]));
    }

    @Test
    void fullDepthScanMatchesEveryDecodedInclusionProof(@TempDir Path directory) throws Exception {
        LoadOptions options = options(directory, 100, 20, 100, 8, "none", false);
        new PoseidonMpfLoadRunner(options).run();
        var proofs = new PoseidonMpfProofRunner(options).run();

        var scan = new PoseidonMpfDepthScanRunner(options).run();
        var proofHistogram = proofs.artifacts().stream().collect(java.util.stream.Collectors.groupingBy(
                PoseidonMpfProofRunner.ProofArtifact::steps,
                java.util.TreeMap::new,
                java.util.stream.Collectors.counting()));

        assertEquals(100, scan.entries());
        assertEquals(proofHistogram, scan.stepHistogram());
        assertEquals(proofs.artifacts().stream().mapToInt(
                PoseidonMpfProofRunner.ProofArtifact::steps).max().orElseThrow(), scan.maxProofSteps());
    }

    private static LoadOptions options(
            Path directory,
            long entries,
            int batch,
            int samples,
            int maxSteps,
            String setup,
            boolean allowInsecureSetup) {
        return LoadOptions.parse(new String[]{
                "--stage=all",
                "--work-dir=" + directory,
                "--entries=" + entries,
                "--batch=" + batch,
                "--samples=" + samples,
                "--max-steps=" + maxSteps,
                "--progress-every=0",
                "--setup=" + setup,
                "--allow-insecure-setup=" + allowInsecureSetup
        });
    }

    private static void assertArtifactManifest(
            Path directory, String templateId, String fingerprint) throws Exception {
        var json = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(directory.resolve("manifest.json").toFile());
        assertEquals(templateId, json.path("templateId").asText());
        assertEquals(fingerprint, json.path("exactCircuitFingerprint").asText());
        assertFalse(json.path("productionApproved").asBoolean());
        var fields = json.path("files").fields();
        int files = 0;
        while (fields.hasNext()) {
            var entry = fields.next();
            byte[] value = Files.readAllBytes(directory.resolve(entry.getKey()));
            String digest = java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(value));
            assertEquals(value.length, entry.getValue().path("bytes").asLong());
            assertEquals(digest, entry.getValue().path("sha256").asText());
            files++;
        }
        assertTrue(files >= 12);

        byte[] circuitManifestBytes = Files.readAllBytes(directory.resolve("circuit-manifest.json"));
        String circuitManifestDigest = java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(circuitManifestBytes));
        assertEquals(circuitManifestDigest, json.path("circuitManifestSha256").asText());
        var manifestModel = new com.fasterxml.jackson.databind.ObjectMapper().readValue(
                circuitManifestBytes,
                new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Object>>() {});
        var circuitManifest = com.bloxbean.cardano.zeroj.api.AuthenticatedStateCircuitManifest
                .fromJsonModel(manifestModel);
        assertArrayEquals(circuitManifestBytes, circuitManifest.canonicalJsonBytes());
        assertEquals(templateId, circuitManifest.templateId());
        assertEquals(fingerprint.substring(fingerprint.lastIndexOf("-r") + 2),
                circuitManifest.r1csSha256());

        byte[] encodedVk = Files.readAllBytes(directory.resolve("verification-key.bin"));
        String vkDigest = java.util.HexFormat.of().formatHex(
                java.security.MessageDigest.getInstance("SHA-256").digest(encodedVk));
        assertEquals(vkDigest, json.path("verificationKeySha256").asText());
        assertEquals(vkDigest, circuitManifest.verificationKeySha256());
        assertEquals(2, com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec
                .Groth16VerificationKeyCodec.decode(encodedVk).ic().size());
    }
}
