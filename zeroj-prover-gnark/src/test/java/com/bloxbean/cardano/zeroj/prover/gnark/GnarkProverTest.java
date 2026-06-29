package com.bloxbean.cardano.zeroj.prover.gnark;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.LegacyCurvePolicy;
import com.bloxbean.cardano.zeroj.prover.spi.ProverException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

/**
 * Integration tests for GnarkProver.
 *
 * <p>These tests require the gnark shared library to be built first:
 * {@code make -C zeroj-prover-gnark/gnark-wrapper build}</p>
 *
 * <p>Tests are automatically skipped if the native library is not available.</p>
 */
class GnarkProverTest {

    @AfterEach
    void clearLegacyBn254OptIn() {
        System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
    }

    @Test
    void bn254RejectedByDefault() {
        assumeFalse(LegacyCurvePolicy.legacyBn254Enabled(),
                "External legacy BN254 opt-in is enabled in this environment");

        var curveError = assertThrows(ProverException.class,
                () -> GnarkProver.requireSupportedCurve(CurveId.BN254));
        assertEquals(ProverException.ErrorCode.INVALID_INPUT, curveError.errorCode());
        assertTrue(curveError.getMessage().contains("BN254 is disabled by default"));

        var aliasError = assertThrows(ProverException.class,
                () -> GnarkProver.requireSupportedCurve("bn254"));
        assertEquals(ProverException.ErrorCode.INVALID_INPUT, aliasError.errorCode());
    }

    @Test
    void bn254AllowedWithExplicitLegacyOptIn() {
        System.setProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY, "true");

        assertDoesNotThrow(() -> GnarkProver.requireSupportedCurve(CurveId.BN254));
        assertDoesNotThrow(() -> GnarkProver.requireSupportedCurve("bn254"));
    }

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
