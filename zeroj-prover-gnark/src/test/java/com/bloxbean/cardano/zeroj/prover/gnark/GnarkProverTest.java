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

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void isHealthy_returnsTrue() {
        try (var prover = new GnarkProver()) {
            assertTrue(prover.isHealthy());
        }
    }

    @Test
    @EnabledIf("isNativeLibraryAvailable")
    void listCircuits_returnsEmptyList() {
        try (var prover = new GnarkProver()) {
            assertTrue(prover.listCircuits().isEmpty());
        }
    }

    @Test
    void prove_throwsUnsupportedOperation() {
        // prove(ProveRequest) should throw for native prover
        if (isNativeLibraryAvailable()) {
            try (var prover = new GnarkProver()) {
                assertThrows(UnsupportedOperationException.class,
                        () -> prover.prove(null));
            }
        }
    }

    static boolean isNativeLibraryAvailable() {
        return GnarkNativeLoader.isAvailable();
    }
}
