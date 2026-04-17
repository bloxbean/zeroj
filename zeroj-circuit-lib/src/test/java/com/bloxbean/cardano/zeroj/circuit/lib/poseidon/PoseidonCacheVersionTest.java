package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PoseidonCacheVersionTest {

    @Test
    @DisplayName("CURRENT is stable across calls (derived from static preset constants)")
    void current_isStable() {
        String a = PoseidonCacheVersion.CURRENT;
        String b = PoseidonCacheVersion.CURRENT;
        assertEquals(a, b);
        assertEquals(16, a.length(), "Version should be 16-char truncated SHA-256");
    }

    @Test
    @DisplayName("ensureFresh on empty dir: writes marker, returns true (first-run treated as stale)")
    void ensureFresh_emptyDir_writesMarkerAndReturnsTrue(@TempDir Path tempDir) throws Exception {
        boolean wiped = PoseidonCacheVersion.ensureFresh(tempDir, List.of("*.bin"));
        assertTrue(wiped);
        Path marker = tempDir.resolve(PoseidonCacheVersion.MARKER);
        assertTrue(Files.exists(marker));
        assertEquals(PoseidonCacheVersion.CURRENT,
                Files.readString(marker, StandardCharsets.UTF_8).trim());
    }

    @Test
    @DisplayName("ensureFresh when marker matches: no wipe, returns false")
    void ensureFresh_markerMatches_noWipe(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve(PoseidonCacheVersion.MARKER),
                PoseidonCacheVersion.CURRENT, StandardCharsets.UTF_8);
        Path stale = Files.writeString(tempDir.resolve("setup.bin"), "stale");

        boolean wiped = PoseidonCacheVersion.ensureFresh(tempDir, List.of("*.bin"));
        assertFalse(wiped);
        assertTrue(Files.exists(stale), "File should not be wiped when version matches");
    }

    @Test
    @DisplayName("ensureFresh when marker differs: wipes matching files, preserves non-matching")
    void ensureFresh_markerStale_wipesMatching(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve(PoseidonCacheVersion.MARKER),
                "deadbeefdeadbeef", StandardCharsets.UTF_8);
        Path stale = Files.writeString(tempDir.resolve("setup-gte.bin"), "stale-r1cs");
        Path srs = Files.writeString(tempDir.resolve("srs.bin"), "stale-srs");
        Path trie = Files.createDirectory(tempDir.resolve("dpp-trie"));
        Files.writeString(trie.resolve("rocks.db"), "stale-trie");
        Path keepMe = Files.writeString(tempDir.resolve("products.json"), "app-state");

        boolean wiped = PoseidonCacheVersion.ensureFresh(tempDir,
                List.of("*.bin", "dpp-trie"));
        assertTrue(wiped);
        assertFalse(Files.exists(stale), "stale .bin should be wiped");
        assertFalse(Files.exists(srs), "stale srs.bin should be wiped");
        assertFalse(Files.exists(trie), "stale dpp-trie dir should be wiped");
        assertTrue(Files.exists(keepMe), "non-matching files should be preserved");
        assertEquals(PoseidonCacheVersion.CURRENT,
                Files.readString(tempDir.resolve(PoseidonCacheVersion.MARKER),
                        StandardCharsets.UTF_8).trim());
    }

    @Test
    @DisplayName("ensureFresh supports prefix patterns (setup-*) and exact-name patterns")
    void ensureFresh_supportsPrefixAndExactMatch(@TempDir Path tempDir) throws Exception {
        Files.writeString(tempDir.resolve("setup-a.bin"), "a");
        Files.writeString(tempDir.resolve("setup-b.bin"), "b");
        Files.writeString(tempDir.resolve("other.bin"), "other");
        Files.writeString(tempDir.resolve("exactFile"), "exact");

        PoseidonCacheVersion.ensureFresh(tempDir, List.of("setup-*", "exactFile"));
        assertFalse(Files.exists(tempDir.resolve("setup-a.bin")));
        assertFalse(Files.exists(tempDir.resolve("setup-b.bin")));
        assertTrue(Files.exists(tempDir.resolve("other.bin")), "non-matching .bin should survive");
        assertFalse(Files.exists(tempDir.resolve("exactFile")));
    }

    @Test
    @DisplayName("ensureFresh on missing dir: creates dir and writes marker")
    void ensureFresh_missingDir_createsIt(@TempDir Path tempDir) throws Exception {
        Path target = tempDir.resolve("newdir");
        assertFalse(Files.exists(target));

        boolean wiped = PoseidonCacheVersion.ensureFresh(target, List.of("*.bin"));
        assertTrue(wiped);
        assertTrue(Files.isDirectory(target));
        assertTrue(Files.exists(target.resolve(PoseidonCacheVersion.MARKER)));
    }
}
