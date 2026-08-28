package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParameterFingerprint;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtProfiles;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

final class JmtRunFiles {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String VERSION_POLICY = "cumulative-entry-count-per-batch-v1";

    private final Path workDir;
    private final Path manifestFile;
    private final Path reportFile;
    private final Path rocksDbDir;

    JmtRunFiles(Path workDir) {
        this.workDir = workDir;
        manifestFile = workDir.resolve("manifest.json");
        reportFile = workDir.resolve("report.json");
        rocksDbDir = workDir.resolve("rocksdb");
    }

    Path rocksDbDir() { return rocksDbDir; }
    Path reportFile() { return reportFile; }
    Path cardanoArtifactsDir(
            String templateId, String fingerprint, String verificationKeySha256,
            String bundleSha256) {
        requireSafePathComponent("templateId", templateId);
        requireSafePathComponent("fingerprint", fingerprint);
        requireSafePathComponent("verificationKeySha256", verificationKeySha256);
        requireSafePathComponent("bundleSha256", bundleSha256);
        return workDir.resolve("cardano-artifacts").resolve(templateId).resolve(fingerprint)
                .resolve("vk-" + verificationKeySha256).resolve("bundle-" + bundleSha256);
    }

    Manifest ensureManifest(JmtLoadOptions options) throws IOException {
        Files.createDirectories(workDir);
        if (Files.exists(manifestFile)) {
            Manifest existing = JSON.readValue(manifestFile.toFile(), Manifest.class);
            validateIdentity(existing, options);
            return existing;
        }
        if (Files.exists(rocksDbDir) && directoryHasEntries(rocksDbDir)) {
            throw new IllegalStateException("RocksDB exists without its identity manifest: " + rocksDbDir);
        }
        String now = Instant.now().toString();
        var format = PoseidonJmtProfiles.format();
        Manifest created = new Manifest(
                PoseidonJmtProfile.PROFILE_ID,
                format.hashAlgorithmId(),
                format.hashLength(),
                PoseidonJmtProfile.PROOF_CODEC_ID,
                BuildInfo.cclVersion(),
                BuildInfo.poseidonFingerprint(),
                DeterministicJmtDataset.SCHEMA_ID,
                VERSION_POLICY,
                options.seed(),
                options.entries(),
                options.batchSize(),
                DeterministicJmtDataset.KEY_BYTES,
                DeterministicJmtDataset.VALUE_BYTES,
                0L,
                null,
                null,
                "created",
                now,
                now);
        writeAtomic(manifestFile, created);
        return created;
    }

    Manifest checkpoint(
            Manifest manifest,
            long completed,
            Long latestVersion,
            byte[] root,
            String status) throws IOException {
        Manifest updated = new Manifest(
                manifest.profileId(), manifest.hashAlgorithmId(), manifest.hashLength(),
                manifest.proofCodecId(), manifest.cclVersion(), manifest.poseidonFingerprint(),
                manifest.datasetSchema(), manifest.versionPolicy(), manifest.seed(),
                manifest.targetEntries(), manifest.batchSize(), manifest.keyBytes(),
                manifest.valueBytes(), completed, latestVersion,
                root == null ? null : java.util.HexFormat.of().formatHex(root), status,
                manifest.createdAt(), Instant.now().toString());
        writeAtomic(manifestFile, updated);
        return updated;
    }

    synchronized void writeReportSection(
            String name, Object value, JmtLoadOptions options) throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        if (Files.exists(reportFile)) {
            report.putAll(JSON.readValue(reportFile.toFile(), new TypeReference<>() {}));
        }
        report.put("profileId", PoseidonJmtProfile.PROFILE_ID);
        report.put("cclVersion", BuildInfo.cclVersion());
        report.put("poseidonParameterFingerprint", BuildInfo.poseidonFingerprint());
        report.put("updatedAt", Instant.now().toString());
        report.put(name, value);
        report.put(name + "Provenance", BenchmarkRunProvenance.capture(
                name, BuildInfo.cclVersion(), BuildInfo.poseidonFingerprint(),
                options.reportConfiguration()));
        writeAtomic(reportFile, report);
    }

    void writeCardanoArtifact(Path directory, String name, byte[] value) throws IOException {
        Files.createDirectories(directory);
        writeAtomic(directory.resolve(name), value);
    }

    void writeCardanoArtifactManifest(Path directory, Object value) throws IOException {
        Files.createDirectories(directory);
        writeAtomic(directory.resolve("manifest.json"), value);
    }

    private static void validateIdentity(Manifest manifest, JmtLoadOptions options) {
        var format = PoseidonJmtProfiles.format();
        requireEqual("profileId", PoseidonJmtProfile.PROFILE_ID, manifest.profileId());
        requireEqual("hashAlgorithmId", format.hashAlgorithmId(), manifest.hashAlgorithmId());
        requireEqual("hashLength", format.hashLength(), manifest.hashLength());
        requireEqual("proofCodecId", PoseidonJmtProfile.PROOF_CODEC_ID, manifest.proofCodecId());
        requireCompatibleCclVersion(manifest.cclVersion());
        requireEqual("poseidonFingerprint", BuildInfo.poseidonFingerprint(), manifest.poseidonFingerprint());
        requireEqual("datasetSchema", DeterministicJmtDataset.SCHEMA_ID, manifest.datasetSchema());
        requireEqual("versionPolicy", VERSION_POLICY, manifest.versionPolicy());
        requireEqual("seed", options.seed(), manifest.seed());
        requireEqual("targetEntries", options.entries(), manifest.targetEntries());
        requireEqual("batchSize", options.batchSize(), manifest.batchSize());
        requireEqual("keyBytes", DeterministicJmtDataset.KEY_BYTES, manifest.keyBytes());
        requireEqual("valueBytes", DeterministicJmtDataset.VALUE_BYTES, manifest.valueBytes());
    }

    private static void requireEqual(String name, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw new IllegalStateException("Manifest mismatch for " + name
                    + ": expected " + expected + ", found " + actual);
        }
    }

    private static void requireCompatibleCclVersion(String storedVersion) {
        if (!BuildInfo.isVerifiedStructuresCompatibleCclVersion(storedVersion)) {
            throw new IllegalStateException("Manifest mismatch for cclVersion: expected a "
                    + "verified-structures-compatible baseline for " + BuildInfo.cclVersion()
                    + ", found " + storedVersion);
        }
    }

    private static void requireSafePathComponent(String name, String value) {
        if (value == null || !value.matches("[a-zA-Z0-9._-]+")) {
            throw new IllegalArgumentException(name + " is not a safe artifact identity");
        }
    }

    static long directoryBytes(Path directory) throws IOException {
        if (Files.notExists(directory)) return 0L;
        try (var paths = Files.walk(directory)) {
            return paths.filter(Files::isRegularFile).mapToLong(path -> {
                try {
                    return Files.size(path);
                } catch (IOException error) {
                    throw new DirectorySizeException(error);
                }
            }).sum();
        } catch (DirectorySizeException error) {
            throw error.ioCause;
        }
    }

    private static boolean directoryHasEntries(Path directory) throws IOException {
        try (var entries = Files.list(directory)) {
            return entries.findAny().isPresent();
        }
    }

    private static void writeAtomic(Path target, Object value) throws IOException {
        Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
        JSON.writeValue(temporary.toFile(), value);
        forceFile(temporary);
        moveAtomic(temporary, target);
        forceDirectory(target.getParent());
    }

    private static void writeAtomic(Path target, byte[] value) throws IOException {
        Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(temporary, value);
        forceFile(temporary);
        moveAtomic(temporary, target);
        forceDirectory(target.getParent());
    }

    private static void forceFile(Path file) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    private static void forceDirectory(Path directory) throws IOException {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (UnsupportedOperationException error) {
            throw new IOException("filesystem does not support durable directory checkpoints", error);
        }
    }

    private static void moveAtomic(Path temporary, Path target) throws IOException {
        try {
            Files.move(temporary, target,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException error) {
            throw new IOException(
                    "atomic sidecar replacement is required for durable JMT checkpoints", error);
        }
    }

    record Manifest(
            String profileId,
            String hashAlgorithmId,
            int hashLength,
            String proofCodecId,
            String cclVersion,
            String poseidonFingerprint,
            String datasetSchema,
            String versionPolicy,
            long seed,
            long targetEntries,
            int batchSize,
            int keyBytes,
            int valueBytes,
            long completedEntries,
            Long latestVersion,
            String rootHex,
            String status,
            String createdAt,
            String updatedAt) {}

    private static final class DirectorySizeException extends RuntimeException {
        private final IOException ioCause;
        private DirectorySizeException(IOException cause) {
            super(cause);
            ioCause = cause;
        }
    }
}
