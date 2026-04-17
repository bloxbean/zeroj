package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Detects when persisted ZK caches (SRS, R1CS setup artifacts, Merkle tries)
 * were generated under a different Poseidon parameter set than the current
 * runtime and wipes them so the usecase regenerates fresh.
 *
 * <p>Rationale: R1CS files bake Poseidon constants into their constraint
 * systems. If the code's Poseidon parameters change (e.g. during an
 * ADR-0015-style migration or a future parameter tweak), a cached R1CS is
 * no longer correct for the current runtime. Without this marker, stale
 * caches produce witness-evaluation errors at arbitrary points — the error
 * at the top of the ADR-0015 end-to-end test was exactly this class of bug,
 * manually worked around by {@code rm -rf data}.
 *
 * <p>Version string: SHA-256(committed BN254 + BLS12-381 preset C and M
 * arrays), truncated to 16 hex chars. Any parameter change flips the hash
 * and triggers a wipe on next startup.
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // In your Spring @Configuration or app bootstrap:
 * PoseidonCacheVersion.ensureFresh(
 *     Path.of("./data"),
 *     List.of("*.bin", "dpp-trie", "dpp-trie-minted"));
 * }</pre>
 *
 * <p>The caller owns the list of cache artifacts to wipe; this helper only
 * handles version detection and deletion. Application state (H2 DB, RocksDB
 * rows unrelated to hashing) should not be passed in.
 */
public final class PoseidonCacheVersion {

    /** Marker file name, placed at the root of the data dir. */
    public static final String MARKER = ".zeroj-poseidon-version";

    /**
     * Current Poseidon parameter-set version. Derived from committed BN254 +
     * BLS12-381 preset constants; changes when either preset's constants
     * change.
     */
    public static final String CURRENT = computeCurrent();

    private PoseidonCacheVersion() {}

    private static String computeCurrent() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            hashPreset(md, PoseidonParamsBN254T3.C, PoseidonParamsBN254T3.M);
            hashPreset(md, PoseidonParamsBLS12_381T3.C, PoseidonParamsBLS12_381T3.M);
            byte[] digest = md.digest();
            return HexFormat.of().formatHex(digest).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static void hashPreset(MessageDigest md, java.math.BigInteger[] c, java.math.BigInteger[] m) {
        for (var v : c) md.update(v.toByteArray());
        for (var v : m) md.update(v.toByteArray());
    }

    /**
     * Checks the marker file in {@code dataDir}. If missing or stale, wipes
     * all paths matching the given {@code cachePatterns} (relative to
     * {@code dataDir}; treated as literal filenames or directory names, not
     * glob patterns) and writes a fresh marker.
     *
     * <p>Safe to call on first run — if {@code dataDir} does not exist, it
     * is created and the marker is written.
     *
     * @param dataDir       directory containing ZK cache artifacts
     * @param cachePatterns filename or directory-name matchers under
     *                      {@code dataDir}; supports leading {@code "*."} and
     *                      trailing {@code "*"} for simple prefix/suffix matching
     * @return true if a wipe occurred, false if caches were already current
     */
    public static boolean ensureFresh(Path dataDir, List<String> cachePatterns) {
        try {
            Files.createDirectories(dataDir);
            Path marker = dataDir.resolve(MARKER);
            String stored = Files.exists(marker)
                    ? Files.readString(marker, StandardCharsets.UTF_8).trim()
                    : null;
            if (CURRENT.equals(stored)) {
                return false;
            }
            wipeMatching(dataDir, cachePatterns);
            Files.writeString(marker, CURRENT, StandardCharsets.UTF_8);
            return true;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to validate Poseidon cache version at " + dataDir, e);
        }
    }

    private static void wipeMatching(Path dataDir, List<String> patterns) throws IOException {
        if (!Files.exists(dataDir)) return;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dataDir)) {
            for (Path entry : stream) {
                String name = entry.getFileName().toString();
                if (name.equals(MARKER)) continue;
                if (matchesAny(name, patterns)) {
                    deleteRecursively(entry);
                }
            }
        }
    }

    private static boolean matchesAny(String name, List<String> patterns) {
        for (String p : patterns) {
            if (p.startsWith("*.")) {
                if (name.endsWith(p.substring(1))) return true;
            } else if (p.endsWith("*")) {
                if (name.startsWith(p.substring(0, p.length() - 1))) return true;
            } else if (name.equals(p)) {
                return true;
            }
        }
        return false;
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (Files.isDirectory(path)) {
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(path)) {
                for (Path child : stream) deleteRecursively(child);
            }
        }
        Files.deleteIfExists(path);
    }
}
