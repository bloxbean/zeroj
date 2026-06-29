package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.api.LegacyCurvePolicy;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTau;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

class PlonKLegacyBn254PolicyTest {

    @AfterEach
    void restoreDefaultPolicy() {
        System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
    }

    @Test
    void bn254PlonkApisRequireLegacyOptIn() {
        System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
        assumeFalse(LegacyCurvePolicy.legacyBn254Enabled(),
                "Legacy BN254 is enabled by environment; default-disable assertion is not meaningful");

        assertThrows(IllegalStateException.class,
                () -> PtauImporter.importPtau(new ByteArrayInputStream(new byte[0])));
        assertThrows(IllegalStateException.class,
                () -> PtauImporter.importPtau(new ByteArrayInputStream(new byte[0]), 1));
        assertThrows(IllegalStateException.class,
                () -> PlonKZkeyImporter.importZkey(new ByteArrayInputStream(new byte[0])));
        assertThrows(IllegalStateException.class,
                () -> PowersOfTau.generate(4));
        assertThrows(IllegalStateException.class,
                () -> PlonKSetup.setup(0, 0, new java.math.BigInteger[0][0],
                        new int[0], new int[0], new int[0], 0, null));
        assertThrows(IllegalStateException.class,
                () -> PlonKProver.prove(null, null, null, null, new java.math.BigInteger[0]));
        assertThrows(IllegalStateException.class,
                () -> PlonKProver.proveUnblinded(null, null, null, null, new java.math.BigInteger[0]));
    }
}
