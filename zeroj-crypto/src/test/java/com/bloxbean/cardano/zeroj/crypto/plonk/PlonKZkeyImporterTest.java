package com.bloxbean.cardano.zeroj.crypto.plonk;

import com.bloxbean.cardano.zeroj.api.LegacyCurvePolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class PlonKZkeyImporterTest {

    private static final String ZKEY_PATH = "/test-circuits/plonk-multiplier/multiplier_plonk.zkey";

    @BeforeEach
    void enableLegacyBn254() {
        System.setProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY, "true");
    }

    @AfterEach
    void clearLegacyBn254() {
        System.clearProperty(LegacyCurvePolicy.ALLOW_LEGACY_BN254_PROPERTY);
    }

    @Test
    void importZkey_parsesSuccessfully() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        assertNotNull(pk);
        assertEquals(8, pk.domainSize());
        assertEquals(2, pk.nPublic());
        assertEquals(3, pk.nConstraints());
        assertEquals(BigInteger.TWO, pk.k1());
        assertEquals(BigInteger.valueOf(3), pk.k2());
    }

    @Test
    void importZkey_selectorPolynomialsLoaded() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        assertEquals(8, pk.ql().length, "Ql should have domainSize evaluations");
        assertEquals(8, pk.qr().length);
        assertEquals(8, pk.qm().length);
        assertEquals(8, pk.qo().length);
        assertEquals(8, pk.qc().length);
    }

    @Test
    void importZkey_permutationPolynomialsLoaded() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        assertEquals(8, pk.s1().length);
        assertEquals(8, pk.s2().length);
        assertEquals(8, pk.s3().length);
    }

    @Test
    void importZkey_srsPointsLoaded() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        assertTrue(pk.srsG1().length > 0, "Should have SRS G1 points");
        assertTrue(pk.srsG1Lagrange().length > 0, "Should have Lagrange SRS points");
        assertFalse(pk.x2().isInfinity(), "X_2 should not be infinity");
    }

    @Test
    void importZkey_commitmentsOnCurve() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        assertTrue(pk.qmCommit().isOnCurve() || pk.qmCommit().isInfinity(), "Qm commitment on curve");
        assertTrue(pk.qlCommit().isOnCurve() || pk.qlCommit().isInfinity(), "Ql commitment on curve");
        assertTrue(pk.s1Commit().isOnCurve() || pk.s1Commit().isInfinity(), "S1 commitment on curve");
        assertTrue(pk.s2Commit().isOnCurve() || pk.s2Commit().isInfinity(), "S2 commitment on curve");
        assertTrue(pk.s3Commit().isOnCurve() || pk.s3Commit().isInfinity(), "S3 commitment on curve");
        assertTrue(pk.x2().isOnCurve(), "X_2 on G2 twist curve");
    }

    @Test
    void importZkey_omegaCorrect() throws IOException {
        var pk = PlonKZkeyImporter.importZkey(getClass().getResourceAsStream(ZKEY_PATH));
        // omega^domainSize should be 1
        var omegaN = pk.omega();
        for (int i = 1; i < pk.domainSize(); i++) omegaN = omegaN.mul(pk.omega());
        assertTrue(omegaN.isOne(), "omega^n should be 1");
    }
}
