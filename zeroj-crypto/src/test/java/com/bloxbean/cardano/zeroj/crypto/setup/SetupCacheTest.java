package com.bloxbean.cardano.zeroj.crypto.setup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SetupCacheTest {

    @TempDir
    Path tempDir;

    @Test
    void srsCacheRoundTripsCanonicalBls381MontgomeryLimbs() throws Exception {
        var srs = PowersOfTauBLS381.generate(4);
        Path path = tempDir.resolve("srs.bin");

        SetupCache.saveSrs(srs, path);
        var loaded = SetupCache.loadSrs(path);

        assertEquals(srs.power(), loaded.power());
        assertEquals(srs.tauScalar(), loaded.tauScalar());
        assertArrayEquals(srs.tauG1(), loaded.tauG1());
        assertArrayEquals(srs.tauG2(), loaded.tauG2());
    }
}
