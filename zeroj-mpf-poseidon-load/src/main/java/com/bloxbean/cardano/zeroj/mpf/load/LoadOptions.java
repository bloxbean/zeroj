package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.rocksdb.RocksDbConfig;

import java.nio.file.Path;
import java.util.Locale;

public record LoadOptions(
        Stage stage,
        Path workDir,
        long entries,
        int batchSize,
        long seed,
        int samples,
        int maxSteps,
        int maxForkPrefixChunks,
        int pairCacheEntries,
        RocksDbProfile rocksDbProfile,
        long progressEvery,
        boolean wal,
        long depthScanVersion,
        SetupMode setupMode,
        Path keysDir,
        boolean allowInsecureSetup) {

    public static final long DEFAULT_ENTRIES = 5_000_000L;

    public LoadOptions {
        if (entries < 1) throw new IllegalArgumentException("entries must be >= 1");
        if (batchSize < 1) throw new IllegalArgumentException("batch must be >= 1");
        if (samples < 1) throw new IllegalArgumentException("samples must be >= 1");
        if (maxSteps < 0) throw new IllegalArgumentException("max-steps must be >= 0");
        if (maxSteps > 0 && maxForkPrefixChunks < 2) {
            throw new IllegalArgumentException("max-fork-prefix-chunks must be >= 2 when max-steps > 0");
        }
        if (pairCacheEntries < 0) throw new IllegalArgumentException("pair-cache must be >= 0");
        if (progressEvery < 0) throw new IllegalArgumentException("progress-every must be >= 0");
        if (depthScanVersion != -1 && (depthScanVersion < 1 || depthScanVersion > entries)) {
            throw new IllegalArgumentException("depth-scan-version must be -1 or between 1 and entries");
        }
        workDir = workDir.toAbsolutePath().normalize();
        keysDir = keysDir.toAbsolutePath().normalize();
    }

    public static LoadOptions parse(String[] args) {
        Stage stage = Stage.ALL;
        Path workDir = Path.of("build", "poseidon-mpf-5m");
        long entries = DEFAULT_ENTRIES;
        int batch = 1_000;
        long seed = 25L;
        int samples = 32;
        int maxSteps = 8;
        int prefixChunks = 2;
        int pairCache = 262_144;
        RocksDbProfile rocksDbProfile = RocksDbProfile.HIGH_THROUGHPUT;
        long progress = 100_000L;
        boolean wal = true;
        long depthScanVersion = -1L;
        SetupMode setup = SetupMode.NONE;
        Path keysDir = null;
        boolean allowInsecureSetup = false;

        for (String arg : args) {
            if ("--help".equals(arg) || "-h".equals(arg)) throw new HelpRequested();
            String[] pair = split(arg);
            switch (pair[0]) {
                case "stage" -> stage = Stage.parse(pair[1]);
                case "work-dir" -> workDir = Path.of(pair[1]);
                case "entries" -> entries = Long.parseLong(pair[1]);
                case "batch" -> batch = Integer.parseInt(pair[1]);
                case "seed" -> seed = Long.parseLong(pair[1]);
                case "samples" -> samples = Integer.parseInt(pair[1]);
                case "max-steps" -> maxSteps = Integer.parseInt(pair[1]);
                case "max-fork-prefix-chunks" -> prefixChunks = Integer.parseInt(pair[1]);
                case "pair-cache" -> pairCache = Integer.parseInt(pair[1]);
                case "rocksdb-profile" -> rocksDbProfile = RocksDbProfile.parse(pair[1]);
                case "progress-every" -> progress = Long.parseLong(pair[1]);
                case "wal" -> wal = Boolean.parseBoolean(pair[1]);
                case "depth-scan-version" -> depthScanVersion = Long.parseLong(pair[1]);
                case "setup" -> setup = SetupMode.parse(pair[1]);
                case "keys-dir" -> keysDir = Path.of(pair[1]);
                case "allow-insecure-setup" -> allowInsecureSetup = Boolean.parseBoolean(pair[1]);
                default -> throw new IllegalArgumentException("Unknown option --" + pair[0]);
            }
        }
        if (keysDir == null) keysDir = workDir.resolve("groth16-keys");
        return new LoadOptions(stage, workDir, entries, batch, seed, samples, maxSteps,
                prefixChunks, pairCache, rocksDbProfile, progress, wal, depthScanVersion,
                setup, keysDir, allowInsecureSetup);
    }

    private static String[] split(String arg) {
        if (!arg.startsWith("--") || !arg.contains("=")) {
            throw new IllegalArgumentException("Expected --name=value, got: " + arg);
        }
        int equals = arg.indexOf('=');
        return new String[]{arg.substring(2, equals), arg.substring(equals + 1)};
    }

    public enum Stage {
        LOAD, PROOFS, CIRCUIT, DEPTH_SCAN, ALL;

        static Stage parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }

        boolean includes(Stage requested) {
            // A full current-root traversal is intentionally opt-in even when
            // the historical load/proofs/circuit aggregate is selected.
            return this == requested || (this == ALL && requested != DEPTH_SCAN);
        }
    }

    public enum SetupMode {
        NONE, IN_MEMORY, STORE, LOAD;

        static SetupMode parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }
    }

    public enum RocksDbProfile {
        HIGH_THROUGHPUT, BALANCED, LOW_MEMORY, DEFAULT;

        static RocksDbProfile parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }

        RocksDbConfig config() {
            return switch (this) {
                case HIGH_THROUGHPUT -> RocksDbConfig.highThroughput();
                case BALANCED -> RocksDbConfig.balanced();
                case LOW_MEMORY -> RocksDbConfig.lowMemory();
                case DEFAULT -> RocksDbConfig.defaults();
            };
        }
    }

    static final class HelpRequested extends RuntimeException {}
}
