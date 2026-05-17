package com.bloxbean.cardano.zeroj.prover.gnark;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for GnarkProver.
 *
 * <p>These tests require the gnark shared library to be built first:
 * {@code make -C zeroj-prover-gnark/gnark-wrapper build}</p>
 *
 * <p>Tests are automatically skipped if the native library is not available.</p>
 */
class GnarkProverTest {

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void gnarkVersion_returnsVersion() {
        try (var prover = new GnarkProver()) {
            String version = prover.gnarkVersion();
            assertNotNull(version);
            assertFalse(version.isBlank());
            System.out.println("gnark version: " + version);
        }
    }

    static boolean isNativeLibraryAvailable() {
        return GnarkNativeLoader.isAvailable();
    }
}
