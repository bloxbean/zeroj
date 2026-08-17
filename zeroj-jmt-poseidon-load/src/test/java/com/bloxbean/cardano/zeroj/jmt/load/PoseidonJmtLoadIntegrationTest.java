package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.JellyfishMerkleTree;
import com.bloxbean.cardano.vds.jmt.JmtProfile;
import com.bloxbean.cardano.vds.jmt.integrity.JmtIntegrityChecker;
import com.bloxbean.cardano.vds.jmt.integrity.JmtIntegrityMode;
import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;
import com.bloxbean.cardano.vds.jmt.store.JmtFormatMismatchException;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtProfiles;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtTree;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class PoseidonJmtLoadIntegrationTest {

    @Test
    void pre5ReleaseReopensTheSourceIdenticalDev1StoreButNoOtherCclVersion(
            @TempDir Path directory) throws Exception {
        JmtLoadOptions options = options(directory, 20, 10, 4, 8, "none", false);
        var loaded = new PoseidonJmtLoadRunner(options).run();
        Path manifestPath = directory.resolve("manifest.json");
        var json = new com.fasterxml.jackson.databind.ObjectMapper();
        var manifest = (com.fasterxml.jackson.databind.node.ObjectNode) json.readTree(
                manifestPath.toFile());
        manifest.put("cclVersion", "0.8.0-pre5-dev1");
        json.writeValue(manifestPath.toFile(), manifest);

        assertEquals(loaded.rootHex(), new PoseidonJmtLoadRunner(options).run().rootHex());
        assertEquals(4, new PoseidonJmtProofRunner(options).run().artifacts().size());

        manifest.put("cclVersion", "0.8.0-pre5-dev2");
        json.writeValue(manifestPath.toFile(), manifest);
        IllegalStateException rejected = assertThrows(
                IllegalStateException.class, () -> new PoseidonJmtLoadRunner(options).run());
        assertTrue(rejected.getMessage().contains("verified-structures-compatible baseline"));
    }

    @Test
    void durableLoadResumesAtCommittedVersionsAndProofsVerify(@TempDir Path directory)
            throws Exception {
        JmtLoadOptions options = options(directory, 100, 20, 16, 8, "none", false);
        IllegalStateException interruption = assertThrows(IllegalStateException.class,
                () -> new PoseidonJmtLoadRunner(options, (completed, root) -> {
                    if (completed == 40) throw new IllegalStateException("injected interruption");
                }).run());
        assertEquals("injected interruption", interruption.getMessage());

        var resumed = new PoseidonJmtLoadRunner(options).run();
        var reopened = new PoseidonJmtLoadRunner(options).run();
        assertEquals(40, resumed.resumedFrom());
        assertEquals(100, resumed.latestVersion());
        assertEquals(100, reopened.resumedFrom());
        assertEquals(0, reopened.checkpointsWritten());
        assertEquals(resumed.rootHex(), reopened.rootHex());
        assertTrue(resumed.databaseBytesAfter() > 0);
        assertTrue(resumed.productionDurabilityOptions());
        assertTrue(resumed.peakObservedRssBytes() > 0 || "unsupported".equals(resumed.rssSource()));

        var proofs = new PoseidonJmtProofRunner(options).run();
        assertEquals(16, proofs.artifacts().size());
        assertTrue(proofs.artifacts().stream().allMatch(item -> item.levels() <= 8));
        assertTrue(proofs.result().nativeWireBytes().minimum() > 0);
        assertArrayEquals(java.util.HexFormat.of().parseHex(resumed.rootHex()), proofs.root());
        assertTrue(Files.isRegularFile(directory.resolve("manifest.json")));
        assertTrue(Files.isRegularFile(directory.resolve("report.json")));
    }

    @Test
    void resumeRefusesToAdoptDurableStateAheadOfAuthenticatedManifest(@TempDir Path directory)
            throws Exception {
        JmtLoadOptions options = options(directory, 100, 20, 4, 8, "none", false);
        assertThrows(IllegalStateException.class,
                () -> new PoseidonJmtLoadRunner(options, (completed, root) -> {
                    if (completed == 40) throw new IllegalStateException("stop-after-checkpoint");
                }).run());

        byte[] foreignRoot;
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                directory.resolve("rocksdb").toString(), options.storeOptions())) {
            foreignRoot = new PoseidonJmtTree(store).put(
                    60, Map.of(bytes("foreign-key"), bytes("foreign-value"))).rootHash();
        }

        IllegalStateException rejected = assertThrows(
                IllegalStateException.class, () -> new PoseidonJmtLoadRunner(options).run());
        assertTrue(rejected.getMessage().contains("refusing to adopt unverified commits"));
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                directory.resolve("rocksdb").toString(), options.storeOptions())) {
            assertEquals(60, store.latestRoot().orElseThrow().version());
            assertArrayEquals(foreignRoot, store.latestRoot().orElseThrow().rootHash());
        }
        var manifest = new com.fasterxml.jackson.databind.ObjectMapper()
                .readTree(directory.resolve("manifest.json").toFile());
        assertEquals(40, manifest.path("completedEntries").asLong());
    }

    @Test
    void formatHistoricalReplayRollbackAndPrunePoliciesAreFailClosed(@TempDir Path directory) {
        Path database = directory.resolve("lifecycle");
        var options = JmtLoadOptions.parse(new String[]{
                "--work-dir=" + directory.resolve("unused"), "--entries=1"}).storeOptions();
        byte[] root1;
        byte[] root2;
        byte[] key = bytes("shared");
        try (RocksDbJmtStore store = RocksDbJmtStore.open(database.toString(), options)) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            root1 = tree.put(1, Map.of(key, bytes("v1"))).rootHash();
            root2 = tree.put(2, Map.of(key, bytes("v2"), bytes("other"), bytes("x"))).rootHash();

            assertTrue(tree.verifyInclusionProof(root1, key, bytes("v1"),
                    tree.getProof(key, 1).orElseThrow()));
            assertTrue(tree.verifyInclusionProof(root2, key, bytes("v2"),
                    tree.getProof(key, 2).orElseThrow()));
            assertArrayEquals(root2, tree.put(2,
                    Map.of(key, bytes("v2"), bytes("other"), bytes("x"))).rootHash());
            assertThrows(IllegalArgumentException.class,
                    () -> tree.put(1, Map.of(key, bytes("v1"))));

            store.truncateAfter(1);
            assertArrayEquals(root1, store.latestRoot().orElseThrow().rootHash());
            assertTrue(tree.verifyInclusionProof(root1, key, bytes("v1"),
                    tree.getProof(key, 1).orElseThrow()));
            root2 = tree.put(2, Map.of(key, bytes("v2"))).rootHash();
            store.pruneUpTo(2);
            assertTrue(store.rootHash(1).isEmpty());
            assertTrue(tree.verifyInclusionProof(root2, key, bytes("v2"),
                    tree.getProof(key, 2).orElseThrow()));
            assertThrows(IllegalStateException.class, () -> store.truncateAfter(1));
            assertThrows(IllegalArgumentException.class, () -> store.pruneUpTo(-1));
            assertTrue(new JmtIntegrityChecker(store, PoseidonJmtProfiles.v1())
                    .check(JmtIntegrityMode.FULL).healthy());
        }

        try (RocksDbJmtStore store = RocksDbJmtStore.open(database.toString(), options)) {
            assertThrows(JmtFormatMismatchException.class,
                    () -> new JellyfishMerkleTree(store, JmtProfile.classicBlake2b256V1()));
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            assertTrue(tree.verifyInclusionProof(root2, key, bytes("v2"),
                    tree.getProof(key, 2).orElseThrow()));
        }
    }

    @Test
    void abruptProcessTerminationLeavesOneCompletePoseidonVersion(@TempDir Path directory)
            throws Exception {
        Path database = directory.resolve("crash");
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                database.toString(), productionOptions(directory))) {
            new PoseidonJmtTree(store).put(1, Map.of(bytes("seed"), bytes("one")));
        }

        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process process = new ProcessBuilder(
                java, "-cp", System.getProperty("java.class.path"),
                PoseidonJmtCrashWorker.class.getName(), database.toString(), "5")
                .redirectErrorStream(true)
                .start();
        assertTrue(process.waitFor(Duration.ofSeconds(30).toMillis(), TimeUnit.MILLISECONDS));
        byte[] output = process.getInputStream().readAllBytes();
        assertEquals(0, process.exitValue(), () -> new String(output, StandardCharsets.UTF_8));

        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                database.toString(), productionOptions(directory))) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            assertEquals(5, store.latestRoot().orElseThrow().version());
            byte[] key = bytes("crash-key-5");
            byte[] value = bytes("crash-value-5");
            byte[] root = store.latestRoot().orElseThrow().rootHash();
            assertTrue(tree.verifyInclusionProof(root, key, value,
                    tree.getProof(key, 5).orElseThrow()));
            assertTrue(new JmtIntegrityChecker(store, PoseidonJmtProfiles.v1())
                    .check(JmtIntegrityMode.FULL).healthy());
        }
    }

    @Test
    void forcedTerminationAtCommitBoundaryLeavesNoPartialJmtVersion(@TempDir Path directory)
            throws Exception {
        Path database = directory.resolve("inflight-crash");
        Path marker = directory.resolve("commit-entered.marker");
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                database.toString(), productionOptions(directory))) {
            new PoseidonJmtTree(store).put(1, Map.of(bytes("seed"), bytes("one")));
        }

        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        Process process = new ProcessBuilder(
                java, "-cp", System.getProperty("java.class.path"),
                PoseidonJmtInflightCrashWorker.class.getName(),
                database.toString(), marker.toString(), "5000")
                .redirectErrorStream(true)
                .start();
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (Files.notExists(marker) && process.isAlive() && System.nanoTime() < deadline) {
            Thread.sleep(5);
        }
        assertTrue(Files.exists(marker), () -> {
            try {
                return new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            } catch (Exception error) {
                return error.toString();
            }
        });
        process.destroyForcibly();
        assertTrue(process.waitFor(Duration.ofSeconds(30).toMillis(), TimeUnit.MILLISECONDS));

        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                database.toString(), productionOptions(directory))) {
            PoseidonJmtTree tree = new PoseidonJmtTree(store);
            var latest = store.latestRoot().orElseThrow();
            assertTrue(latest.version() == 1 || latest.version() == 2,
                    "an interrupted atomic commit must expose either the old or complete new head");
            if (latest.version() == 1) {
                assertTrue(tree.verifyInclusionProof(
                        latest.rootHash(), bytes("seed"), bytes("one"),
                        tree.getProof(bytes("seed"), 1).orElseThrow()));
            } else {
                assertTrue(tree.verifyInclusionProof(
                        latest.rootHash(), bytes("inflight-key-4999"),
                        bytes("inflight-value-4999"),
                        tree.getProof(bytes("inflight-key-4999"), 2).orElseThrow()));
            }
            assertTrue(new JmtIntegrityChecker(store, PoseidonJmtProfiles.v1())
                    .check(JmtIntegrityMode.FULL).healthy());
        }
    }

    @Test
    void oneEntryCircuitProducesAndRejectsMutatedPublicInput(@TempDir Path directory)
            throws Exception {
        JmtLoadOptions options = options(directory, 1, 1, 1, 0, "in-memory", true);
        new PoseidonJmtLoadRunner(options).run();
        var proofs = new PoseidonJmtProofRunner(options).run();
        var circuit = new PoseidonJmtCircuitBenchmark(options).run(proofs);
        assertEquals(0, circuit.observedProofLevels());
        assertTrue(circuit.constraints() > 0);
        assertEquals(Boolean.TRUE, circuit.positiveVerified());
        assertEquals(Boolean.TRUE, circuit.negativeInputRejected());
        assertEquals(192, circuit.compressedProofBytes());
        Path artifacts = Path.of(circuit.cardanoArtifactsDirectory());
        assertTrue(artifacts.startsWith(directory.resolve("cardano-artifacts")
                .resolve(circuit.templateId()).resolve(circuit.fingerprint())));
        assertArtifactManifest(artifacts, circuit.templateId(), circuit.fingerprint());
    }

    @Test
    void updateRollbackReopenAndPruneBenchmarkPreservesPrimaryRoot(@TempDir Path directory)
            throws Exception {
        JmtLoadOptions options = options(directory, 100, 20, 4, 8, "none", false);
        var load = new PoseidonJmtLoadRunner(options).run();
        var result = new PoseidonJmtOperationBenchmark(options).run();
        assertTrue(result.scratchDatabaseCopySeconds() > 0);
        assertTrue(result.scratchDatabaseBytes() > 0);
        assertTrue(result.updateSeconds() > 0);
        assertTrue(result.rollbackSeconds() > 0);
        assertTrue(result.reopenAndVerifySeconds() > 0);
        assertTrue(result.prune().recordsPruned() > 0);
        assertTrue(Files.isDirectory(Path.of(result.prune().retainedScratchDirectory())));
        try (var children = Files.list(directory)) {
            assertTrue(children.noneMatch(path -> path.getFileName().toString()
                    .startsWith("operation-update-scratch-")));
        }
        assertEquals(load.rootHex(), new PoseidonJmtLoadRunner(options).run().rootHex());
    }

    @Test
    void operationBenchmarkNeverTruncatesAnUnownedHead(@TempDir Path directory) throws Exception {
        JmtLoadOptions options = options(directory, 40, 20, 2, 8, "none", false);
        new PoseidonJmtLoadRunner(options).run();
        byte[] foreignRoot;
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                directory.resolve("rocksdb").toString(), options.storeOptions())) {
            foreignRoot = new PoseidonJmtTree(store).put(
                    41, Map.of(bytes("unowned-head"), bytes("must-survive"))).rootHash();
        }
        assertThrows(IllegalStateException.class,
                () -> new PoseidonJmtOperationBenchmark(options).run());
        try (RocksDbJmtStore store = RocksDbJmtStore.open(
                directory.resolve("rocksdb").toString(), options.storeOptions())) {
            assertEquals(41, store.latestRoot().orElseThrow().version());
            assertArrayEquals(foreignRoot, store.latestRoot().orElseThrow().rootHash());
        }
    }

    @Test
    void deterministicDatasetKeysAreUniqueAndValuesExerciseFallback() {
        byte[][] keys = new byte[1_000][];
        for (int index = 0; index < keys.length; index++) {
            keys[index] = DeterministicJmtDataset.key(42, index);
            assertEquals(24, keys[index].length);
            assertEquals(0xff, DeterministicJmtDataset.value(42, index)[0] & 0xff);
        }
        for (int index = 1; index < keys.length; index++) {
            assertFalse(Arrays.equals(keys[index - 1], keys[index]));
        }
    }

    @Test
    void exactDepthScanMatchesEveryRealCclInclusionProof(@TempDir Path directory)
            throws Exception {
        JmtLoadOptions options = options(directory, 257, 257, 257, 64, "none", false);
        new PoseidonJmtLoadRunner(options).run();
        var proofs = new PoseidonJmtProofRunner(options).run();

        var scan = new PoseidonJmtDepthScanRunner(options).run();
        var proofHistogram = proofs.artifacts().stream().collect(
                java.util.stream.Collectors.groupingBy(
                        PoseidonJmtProofRunner.ProofArtifact::levels,
                        java.util.TreeMap::new,
                        java.util.stream.Collectors.counting()));

        assertTrue(scan.exactForManifestDataset());
        assertEquals(PoseidonJmtDepthScanRunner.METHOD, scan.method());
        assertEquals(257, scan.entries());
        assertEquals(proofHistogram, scan.depthHistogram());
        assertEquals(proofs.artifacts().stream().mapToInt(
                PoseidonJmtProofRunner.ProofArtifact::levels).max().orElseThrow(),
                scan.maxProofLevels());
    }

    private static RocksDbJmtStore.Options productionOptions(Path directory) {
        return JmtLoadOptions.parse(new String[]{
                "--work-dir=" + directory.resolve("opts"), "--entries=1"}).storeOptions();
    }

    private static JmtLoadOptions options(
            Path directory, long entries, int batch, int samples, int levels,
            String setup, boolean allowInsecure) {
        return JmtLoadOptions.parse(new String[]{
                "--stage=all",
                "--work-dir=" + directory,
                "--entries=" + entries,
                "--batch=" + batch,
                "--samples=" + samples,
                "--max-levels=" + levels,
                "--progress-every=0",
                "--setup=" + setup,
                "--allow-insecure-setup=" + allowInsecure
        });
    }

    private static byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
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
