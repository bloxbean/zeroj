package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.vds.rocksdb.RocksDbConfig;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public record LoadOptions(
        Stage stage,
        Path workDir,
        long entries,
        int batchSize,
        long seed,
        int samples,
        int maxSteps,
        int circuitTrials,
        int pairCacheEntries,
        RocksDbProfile rocksDbProfile,
        long progressEvery,
        boolean wal,
        boolean sync,
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
        if (circuitTrials < 1) throw new IllegalArgumentException("circuit-trials must be >= 1");
        if (pairCacheEntries < 0) throw new IllegalArgumentException("pair-cache must be >= 0");
        if (progressEvery < 0) throw new IllegalArgumentException("progress-every must be >= 0");
        if (sync && !wal) {
            throw new IllegalArgumentException("sync=true requires WAL; use --sync=false only "
                    + "for explicitly disposable benchmarks");
        }
        if (depthScanVersion != -1 && (depthScanVersion < 1 || depthScanVersion > entries)) {
            throw new IllegalArgumentException("depth-scan-version must be -1 or between 1 and entries");
        }
        workDir = workDir.toAbsolutePath().normalize();
        keysDir = keysDir.toAbsolutePath().normalize();
    }

    public static LoadOptions parse(String[] args) {
        Stage stage = Stage.ALL;
        Path workDir = Path.of(".benchmark-data", "poseidon-mpf-5m");
        long entries = DEFAULT_ENTRIES;
        int batch = 1_000;
        long seed = 25L;
        int samples = 32;
        int maxSteps = 8;
        int circuitTrials = 1;
        int pairCache = 262_144;
        RocksDbProfile rocksDbProfile = RocksDbProfile.HIGH_THROUGHPUT;
        long progress = 100_000L;
        boolean wal = true;
        boolean sync = true;
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
                case "circuit-trials" -> circuitTrials = Integer.parseInt(pair[1]);
                case "pair-cache" -> pairCache = Integer.parseInt(pair[1]);
                case "rocksdb-profile" -> rocksDbProfile = RocksDbProfile.parse(pair[1]);
                case "progress-every" -> progress = Long.parseLong(pair[1]);
                case "wal" -> wal = Boolean.parseBoolean(pair[1]);
                case "sync" -> sync = Boolean.parseBoolean(pair[1]);
                case "depth-scan-version" -> depthScanVersion = Long.parseLong(pair[1]);
                case "setup" -> setup = SetupMode.parse(pair[1]);
                case "keys-dir" -> keysDir = Path.of(pair[1]);
                case "allow-insecure-setup" -> allowInsecureSetup = Boolean.parseBoolean(pair[1]);
                default -> throw new IllegalArgumentException("Unknown option --" + pair[0]);
            }
        }
        if (keysDir == null) keysDir = workDir.resolve("groth16-keys");
        return new LoadOptions(stage, workDir, entries, batch, seed, samples, maxSteps,
                circuitTrials, pairCache, rocksDbProfile, progress, wal, sync, depthScanVersion,
                setup, keysDir, allowInsecureSetup);
    }

    private static String[] split(String arg) {
        if (!arg.startsWith("--") || !arg.contains("=")) {
            throw new IllegalArgumentException("Expected --name=value, got: " + arg);
        }
        int equals = arg.indexOf('=');
        return new String[]{arg.substring(2, equals), arg.substring(equals + 1)};
    }

    Map<String, Object> reportConfiguration() {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("stage", stage.name().toLowerCase(Locale.ROOT));
        values.put("workDir", workDir.toString());
        values.put("entries", entries);
        values.put("batchSize", batchSize);
        values.put("seed", seed);
        values.put("samples", samples);
        values.put("maxSteps", maxSteps);
        values.put("circuitTrials", circuitTrials);
        values.put("pairCacheEntries", pairCacheEntries);
        values.put("rocksDbProfile", rocksDbProfile.name().toLowerCase(Locale.ROOT));
        values.put("progressEvery", progressEvery);
        values.put("wal", wal);
        values.put("sync", sync);
        values.put("depthScanVersion", depthScanVersion);
        values.put("setupMode", setupMode.name().toLowerCase(Locale.ROOT));
        values.put("keysDir", keysDir.toString());
        values.put("allowInsecureSetup", allowInsecureSetup);
        return Map.copyOf(values);
    }

    public enum Stage {
        LOAD, PROOFS, CIRCUIT, DEPTH_SCAN, MIGRATE_PROFILE, ALL;

        static Stage parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }

        boolean includes(Stage requested) {
            // A full current-root traversal is intentionally opt-in even when
            // the historical load/proofs/circuit aggregate is selected.
            return this == requested || (this == ALL
                    && requested != DEPTH_SCAN && requested != MIGRATE_PROFILE);
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
