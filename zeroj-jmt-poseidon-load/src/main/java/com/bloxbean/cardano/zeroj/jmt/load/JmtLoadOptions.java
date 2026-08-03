package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbConfig;
import com.bloxbean.cardano.vds.jmt.rocksdb.RocksDbJmtStore;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

public record JmtLoadOptions(
        Stage stage,
        Path workDir,
        long entries,
        int batchSize,
        long seed,
        int samples,
        int maxLevels,
        int circuitTrials,
        int operationEntries,
        int pairCacheEntries,
        RocksProfile rocksProfile,
        long progressEvery,
        SetupMode setupMode,
        Path keysDir,
        boolean allowInsecureSetup) {

    public static final long DEFAULT_ENTRIES = 5_000_000L;

    public JmtLoadOptions {
        if (entries < 1) throw new IllegalArgumentException("entries must be >= 1");
        if (batchSize < 1) throw new IllegalArgumentException("batch must be >= 1");
        if (samples < 1) throw new IllegalArgumentException("samples must be >= 1");
        if (maxLevels < 0 || maxLevels > 64) {
            throw new IllegalArgumentException("max-levels must be in [0, 64]");
        }
        if (circuitTrials < 1) throw new IllegalArgumentException("circuit-trials must be >= 1");
        if (operationEntries < 1) throw new IllegalArgumentException("operation-entries must be >= 1");
        if (pairCacheEntries < 0) throw new IllegalArgumentException("pair-cache must be >= 0");
        if (progressEvery < 0) throw new IllegalArgumentException("progress-every must be >= 0");
        workDir = workDir.toAbsolutePath().normalize();
        keysDir = keysDir.toAbsolutePath().normalize();
    }

    public static JmtLoadOptions parse(String[] arguments) {
        Stage stage = Stage.ALL;
        Path workDir = Path.of(".benchmark-data", "poseidon-jmt-5m");
        long entries = DEFAULT_ENTRIES;
        int batchSize = 5_000;
        long seed = 42L;
        int samples = 32;
        int maxLevels = 64;
        int circuitTrials = 1;
        int operationEntries = 1_000;
        int pairCacheEntries = 262_144;
        RocksProfile rocksProfile = RocksProfile.HIGH_THROUGHPUT;
        long progressEvery = 100_000L;
        SetupMode setupMode = SetupMode.NONE;
        Path keysDir = null;
        boolean allowInsecureSetup = false;
        for (String argument : arguments) {
            if ("--help".equals(argument) || "-h".equals(argument)) throw new HelpRequested();
            String[] pair = split(argument);
            switch (pair[0]) {
                case "stage" -> stage = Stage.parse(pair[1]);
                case "work-dir" -> workDir = Path.of(pair[1]);
                case "entries" -> entries = Long.parseLong(pair[1]);
                case "batch" -> batchSize = Integer.parseInt(pair[1]);
                case "seed" -> seed = Long.parseLong(pair[1]);
                case "samples" -> samples = Integer.parseInt(pair[1]);
                case "max-levels" -> maxLevels = Integer.parseInt(pair[1]);
                case "circuit-trials" -> circuitTrials = Integer.parseInt(pair[1]);
                case "operation-entries" -> operationEntries = Integer.parseInt(pair[1]);
                case "pair-cache" -> pairCacheEntries = Integer.parseInt(pair[1]);
                case "rocksdb-profile" -> rocksProfile = RocksProfile.parse(pair[1]);
                case "progress-every" -> progressEvery = Long.parseLong(pair[1]);
                case "setup" -> setupMode = SetupMode.parse(pair[1]);
                case "keys-dir" -> keysDir = Path.of(pair[1]);
                case "allow-insecure-setup" -> allowInsecureSetup = Boolean.parseBoolean(pair[1]);
                default -> throw new IllegalArgumentException("Unknown option --" + pair[0]);
            }
        }
        if (keysDir == null) keysDir = workDir.resolve("groth16-keys");
        return new JmtLoadOptions(stage, workDir, entries, batchSize, seed, samples,
                maxLevels, circuitTrials, operationEntries, pairCacheEntries,
                rocksProfile, progressEvery,
                setupMode, keysDir, allowInsecureSetup);
    }

    RocksDbJmtStore.Options storeOptions() {
        RocksDbJmtStore.Options options = RocksDbJmtStore.Options.builder()
                .enableRollbackIndex(true)
                .disableWalForBatches(false)
                .syncOnCommit(true)
                .syncOnPrune(true)
                .syncOnTruncate(true)
                .rocksDbConfig(rocksProfile.config())
                .build();
        if (!options.isProductionDurable()) {
            throw new IllegalStateException("JMT benchmark requires CCL production durability options");
        }
        return options;
    }

    Map<String, Object> reportConfiguration() {
        Map<String, Object> values = new LinkedHashMap<>();
        values.put("stage", stage.name().toLowerCase(Locale.ROOT));
        values.put("workDir", workDir.toString());
        values.put("entries", entries);
        values.put("batchSize", batchSize);
        values.put("seed", seed);
        values.put("samples", samples);
        values.put("maxLevels", maxLevels);
        values.put("circuitTrials", circuitTrials);
        values.put("operationEntries", operationEntries);
        values.put("pairCacheEntries", pairCacheEntries);
        values.put("rocksDbProfile", rocksProfile.name().toLowerCase(Locale.ROOT));
        values.put("progressEvery", progressEvery);
        values.put("setupMode", setupMode.name().toLowerCase(Locale.ROOT));
        values.put("keysDir", keysDir.toString());
        values.put("allowInsecureSetup", allowInsecureSetup);
        return Map.copyOf(values);
    }

    private static String[] split(String argument) {
        if (!argument.startsWith("--") || !argument.contains("=")) {
            throw new IllegalArgumentException("Expected --name=value, got: " + argument);
        }
        int equals = argument.indexOf('=');
        return new String[]{argument.substring(2, equals), argument.substring(equals + 1)};
    }

    public enum Stage {
        LOAD, PROOFS, CIRCUIT, DEPTH_SCAN, OPERATIONS, ALL;
        static Stage parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }
        boolean includes(Stage requested) {
            // A complete all-key census is deliberately opt-in; it allocates one 32-byte
            // key hash per leaf and should not surprise ordinary smoke-test users.
            return this == requested || (this == ALL && requested != DEPTH_SCAN);
        }
    }

    public enum SetupMode {
        NONE, IN_MEMORY, STORE, LOAD;
        static SetupMode parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }
    }

    public enum RocksProfile {
        HIGH_THROUGHPUT, BALANCED, LOW_MEMORY, DEFAULT;
        static RocksProfile parse(String value) {
            return valueOf(value.replace('-', '_').toUpperCase(Locale.ROOT));
        }
        @SuppressWarnings("deprecation")
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
