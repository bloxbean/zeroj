package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.core.api.StorageMode;
import com.bloxbean.cardano.vds.mpf.rocksdb.RocksDbStateTrees;
import com.bloxbean.cardano.vds.rocksdb.namespace.NamespaceOptions;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfReference;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.ccl.PoseidonMpfTrie;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

/** One-time, fail-closed metadata migration for the preserved ADR-0041 database. */
public final class PoseidonMpfManifestMigration {
    static final String LEGACY_PROFILE = "zeroj-poseidon-mpf-v2";
    static final String LEGACY_CCL = "0.8.0-pre4";

    private final LoadOptions options;
    private final RunFiles files;

    public PoseidonMpfManifestMigration(LoadOptions options) {
        this.options = Objects.requireNonNull(options, "options");
        this.files = new RunFiles(options.workDir());
    }

    public MigrationResult run() throws IOException {
        RunFiles.Manifest source = files.readManifestUnchecked();
        boolean alreadyMigrated = PoseidonMpfHash.PROFILE_ID.equals(source.profileId());
        if (alreadyMigrated) {
            requireCurrent(source);
            VerificationPass pass = verifyStore(source);
            return new MigrationResult(
                    "already-migrated", source.profileId(), source.profileId(),
                    source.cclVersion(), source.cclVersion(), source.poseidonFingerprint(),
                    source.poseidonFingerprint(), source.rootHex(), pass.samples(),
                    pass.elapsedNanos(), pass.elapsedNanos(), true, true,
                    files.migrationBackupFile().getFileName().toString(), Instant.now().toString());
        }

        requireLegacy(source);
        VerificationPass before = verifyStore(source);
        byte[] originalManifest = Files.readAllBytes(files.manifestFile());
        writeBackup(originalManifest);

        RunFiles.Manifest migrated = new RunFiles.Manifest(
                PoseidonMpfHash.PROFILE_ID,
                BuildInfo.cclVersion(),
                BuildInfo.poseidonFingerprint(),
                source.datasetSchema(),
                source.seed(),
                source.targetEntries(),
                source.batchSize(),
                source.keyBytes(),
                source.valueBytes(),
                source.completedEntries(),
                source.rootHex(),
                source.status(),
                source.createdAt(),
                Instant.now().toString());

        VerificationPass after;
        try {
            files.writeManifest(migrated);
            after = verifyStore(migrated);
            if (!before.rootHex().equals(after.rootHex())) {
                throw new IllegalStateException("MPF root changed across metadata migration");
            }
            if (!before.proofDigests().equals(after.proofDigests())) {
                throw new IllegalStateException("deterministic MPF proofs changed across metadata migration");
            }
        } catch (RuntimeException | IOException failed) {
            files.restoreManifest(originalManifest);
            throw failed;
        }

        MigrationResult result = new MigrationResult(
                "migrated",
                source.profileId(), migrated.profileId(),
                source.cclVersion(), migrated.cclVersion(),
                source.poseidonFingerprint(), migrated.poseidonFingerprint(),
                migrated.rootHex(), before.samples(), before.elapsedNanos(), after.elapsedNanos(),
                true, true, files.migrationBackupFile().getFileName().toString(),
                Instant.now().toString());
        files.writeReportSection("adr0042ProfileMigration", result, options);
        System.out.printf("Migrated MPF manifest %s -> %s; root=%s; samples=%d%n",
                source.profileId(), migrated.profileId(), migrated.rootHex(), before.samples());
        return result;
    }

    private VerificationPass verifyStore(RunFiles.Manifest manifest) {
        long started = System.nanoTime();
        byte[] expectedRoot = parseCanonicalRoot(manifest.rootHex());
        List<String> proofDigests = new ArrayList<>();
        try (RocksDbStateTrees state = new RocksDbStateTrees(
                files.rocksDbDir().toString(), NamespaceOptions.defaults(),
                StorageMode.MULTI_VERSION, options.rocksDbProfile().config())) {
            long version = state.rootsIndex().lastVersion();
            if (version != manifest.completedEntries() || version != manifest.targetEntries()) {
                throw new IllegalStateException("Persisted MPF version " + version
                        + " does not match completed/target entries "
                        + manifest.completedEntries() + "/" + manifest.targetEntries());
            }
            byte[] persistedRoot = state.rootsIndex().latest();
            if (!MessageDigest.isEqual(expectedRoot, persistedRoot)) {
                throw new IllegalStateException("Persisted MPF root does not match manifest root");
            }
            PoseidonMpfTrie trie = PoseidonMpfTrie.create(state.nodeStore(), persistedRoot);
            for (long index : PoseidonMpfProofRunner.sampleIndices(
                    manifest.targetEntries(), options.samples(), manifest.seed())) {
                byte[] key = DeterministicDataset.key(manifest.seed(), index);
                byte[] value = DeterministicDataset.value(manifest.seed(), index);
                if (!Arrays.equals(value, trie.get(key))) {
                    throw new IllegalStateException("Stored value mismatch at migration sample " + index);
                }
                byte[] proof = trie.getProofWire(key).orElseThrow(() ->
                        new IllegalStateException("Missing proof at migration sample " + index));
                if (!trie.verifyProofWire(persistedRoot, key, value, true, proof)
                        || !PoseidonMpfReference.including(persistedRoot, key, value, proof)) {
                    throw new IllegalStateException("Proof verification failed at migration sample " + index);
                }
                proofDigests.add(index + ":" + sha256(proof));
            }
        }
        return new VerificationPass(
                manifest.rootHex(), proofDigests.size(), List.copyOf(proofDigests),
                System.nanoTime() - started);
    }

    private void requireLegacy(RunFiles.Manifest manifest) {
        require("profileId", LEGACY_PROFILE, manifest.profileId());
        require("cclVersion", LEGACY_CCL, manifest.cclVersion());
        require("poseidonFingerprint", BuildInfo.legacyPoseidonFingerprint(), manifest.poseidonFingerprint());
        requireDatasetIdentity(manifest);
        if (!"loaded".equals(manifest.status())) {
            throw new IllegalStateException("Legacy manifest status must be loaded");
        }
    }

    private void requireCurrent(RunFiles.Manifest manifest) {
        require("profileId", PoseidonMpfHash.PROFILE_ID, manifest.profileId());
        if (!BuildInfo.isVerifiedStructuresCompatibleCclVersion(manifest.cclVersion())) {
            throw new IllegalStateException("Current manifest uses an unqualified CCL baseline: "
                    + manifest.cclVersion());
        }
        require("poseidonFingerprint", BuildInfo.poseidonFingerprint(), manifest.poseidonFingerprint());
        requireDatasetIdentity(manifest);
    }

    private void requireDatasetIdentity(RunFiles.Manifest manifest) {
        require("datasetSchema", DeterministicDataset.SCHEMA_ID, manifest.datasetSchema());
        require("seed", options.seed(), manifest.seed());
        require("targetEntries", options.entries(), manifest.targetEntries());
        require("batchSize", options.batchSize(), manifest.batchSize());
        require("keyBytes", DeterministicDataset.KEY_BYTES, manifest.keyBytes());
        require("valueBytes", DeterministicDataset.VALUE_BYTES, manifest.valueBytes());
        if (manifest.completedEntries() != manifest.targetEntries()) {
            throw new IllegalStateException("Only a completed benchmark database may be migrated");
        }
        parseCanonicalRoot(manifest.rootHex());
    }

    private void writeBackup(byte[] original) throws IOException {
        var backup = files.migrationBackupFile();
        if (Files.exists(backup)) {
            if (!MessageDigest.isEqual(original, Files.readAllBytes(backup))) {
                throw new IllegalStateException("Migration backup already exists with different content: " + backup);
            }
            return;
        }
        Files.write(backup, original, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static byte[] parseCanonicalRoot(String rootHex) {
        if (rootHex == null || !rootHex.matches("[0-9a-f]{64}")) {
            throw new IllegalStateException("Manifest root must be 32-byte lowercase hex");
        }
        byte[] root = HexFormat.of().parseHex(rootHex);
        PoseidonMpfHash.fieldFromDigestBytes(root);
        return root;
    }

    private static void require(String name, Object expected, Object actual) {
        if (!Objects.equals(expected, actual)) {
            throw new IllegalStateException("Legacy manifest mismatch for " + name
                    + ": expected " + expected + ", found " + actual);
        }
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private record VerificationPass(
            String rootHex, int samples, List<String> proofDigests, long elapsedNanos) {}

    public record MigrationResult(
            String status,
            String oldProfileId,
            String newProfileId,
            String oldCclVersion,
            String newCclVersion,
            String oldPoseidonFingerprint,
            String newPoseidonFingerprint,
            String rootHex,
            int samples,
            long preMigrationVerificationNanos,
            long postMigrationVerificationNanos,
            boolean rootUnchanged,
            boolean proofsUnchanged,
            String backupManifest,
            String completedAt) {}
}
