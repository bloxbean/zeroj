package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHash;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

final class RunFiles {
    private static final ObjectMapper JSON = new ObjectMapper()
            .findAndRegisterModules()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private final Path workDir;
    private final Path manifestFile;
    private final Path reportFile;
    private final Path rocksDbDir;

    RunFiles(Path workDir) {
        this.workDir = workDir;
        this.manifestFile = workDir.resolve("manifest.json");
        this.reportFile = workDir.resolve("report.json");
        this.rocksDbDir = workDir.resolve("rocksdb");
    }

    Path rocksDbDir() {
        return rocksDbDir;
    }

    Path cardanoArtifactsDir() {
        return workDir.resolve("cardano-artifacts");
    }

    void writeCardanoArtifact(String name, byte[] bytes) throws IOException {
        Path directory = cardanoArtifactsDir();
        Files.createDirectories(directory);
        writeAtomic(directory.resolve(name), bytes);
    }

    Manifest ensureManifest(LoadOptions options) throws IOException {
        Files.createDirectories(workDir);
        if (Files.exists(manifestFile)) {
            Manifest existing = JSON.readValue(manifestFile.toFile(), Manifest.class);
            validateIdentity(existing, options);
            return existing;
        }
        if (Files.exists(rocksDbDir) && directoryHasEntries(rocksDbDir)) {
            throw new IllegalStateException("RocksDB exists without manifest: " + rocksDbDir);
        }
        String now = Instant.now().toString();
        Manifest created = new Manifest(
                PoseidonMpfHash.PROFILE_ID,
                BuildInfo.cclVersion(),
                BuildInfo.poseidonFingerprint(),
                DeterministicDataset.SCHEMA_ID,
                options.seed(),
                options.entries(),
                options.batchSize(),
                DeterministicDataset.KEY_BYTES,
                DeterministicDataset.VALUE_BYTES,
                0L,
                null,
                "created",
                now,
                now);
        writeAtomic(manifestFile, created);
        return created;
    }

    Manifest checkpoint(Manifest manifest, long completed, byte[] root, String status) throws IOException {
        Manifest updated = new Manifest(
                manifest.profileId(), manifest.cclVersion(), manifest.poseidonFingerprint(),
                manifest.datasetSchema(), manifest.seed(), manifest.targetEntries(),
                manifest.batchSize(), manifest.keyBytes(), manifest.valueBytes(), completed,
                root == null ? null : java.util.HexFormat.of().formatHex(root), status,
                manifest.createdAt(), Instant.now().toString());
        writeAtomic(manifestFile, updated);
        return updated;
    }

    synchronized void writeReportSection(String name, Object section) throws IOException {
        Map<String, Object> report = new LinkedHashMap<>();
        if (Files.exists(reportFile)) {
            report.putAll(JSON.readValue(reportFile.toFile(), new TypeReference<>() {}));
        }
        report.put("profileId", PoseidonMpfHash.PROFILE_ID);
        report.put("cclVersion", BuildInfo.cclVersion());
        report.put("updatedAt", Instant.now().toString());
        report.put(name, section);
        writeAtomic(reportFile, report);
    }

    private static void validateIdentity(Manifest manifest, LoadOptions options) {
        requireEqual("profileId", PoseidonMpfHash.PROFILE_ID, manifest.profileId());
        requireEqual("cclVersion", BuildInfo.cclVersion(), manifest.cclVersion());
        requireEqual("poseidonFingerprint", BuildInfo.poseidonFingerprint(), manifest.poseidonFingerprint());
        requireEqual("datasetSchema", DeterministicDataset.SCHEMA_ID, manifest.datasetSchema());
        requireEqual("seed", options.seed(), manifest.seed());
        requireEqual("targetEntries", options.entries(), manifest.targetEntries());
        requireEqual("keyBytes", DeterministicDataset.KEY_BYTES, manifest.keyBytes());
        requireEqual("valueBytes", DeterministicDataset.VALUE_BYTES, manifest.valueBytes());
    }

    private static void requireEqual(String name, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw new IllegalStateException("Manifest mismatch for " + name + ": expected "
                    + expected + ", found " + actual);
        }
    }

    private static boolean directoryHasEntries(Path dir) throws IOException {
        try (var entries = Files.list(dir)) {
            return entries.findAny().isPresent();
        }
    }

    private static void writeAtomic(Path target, Object value) throws IOException {
        Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
        JSON.writeValue(temporary.toFile(), value);
        try {
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void writeAtomic(Path target, byte[] value) throws IOException {
        Path temporary = target.resolveSibling(target.getFileName() + ".tmp");
        Files.write(temporary, value);
        try {
            Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    static long directoryBytes(Path directory) throws IOException {
        if (Files.notExists(directory)) return 0L;
        try (var paths = Files.walk(directory)) {
            return paths.filter(Files::isRegularFile).mapToLong(path -> {
                try {
                    return Files.size(path);
                } catch (IOException e) {
                    throw new DirectorySizeException(e);
                }
            }).sum();
        } catch (DirectorySizeException e) {
            throw e.cause;
        }
    }

    record Manifest(
            String profileId,
            String cclVersion,
            String poseidonFingerprint,
            String datasetSchema,
            long seed,
            long targetEntries,
            int batchSize,
            int keyBytes,
            int valueBytes,
            long completedEntries,
            String rootHex,
            String status,
            String createdAt,
            String updatedAt) {}

    private static final class DirectorySizeException extends RuntimeException {
        private final IOException cause;

        private DirectorySizeException(IOException cause) {
            super(cause);
            this.cause = cause;
        }
    }
}
