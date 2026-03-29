package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG1BN254;
import com.bloxbean.cardano.zeroj.crypto.ec.JacobianG2BN254;
import com.bloxbean.cardano.zeroj.crypto.field.MontFp254;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for .zkey file import and end-to-end Groth16 proving.
 */
class ZkeyImporterTest {

    private static final String ZKEY_PATH = "/test-circuits/multiplier/multiplier.zkey";

    // --- Import tests ---

    @Test
    void importZkey_multiplier_parsesSuccessfully() throws IOException {
        var pk = loadProvingKey();
        assertNotNull(pk);

        // Multiplier circuit: c = a * b
        // Wire 0=1, Wire 1=c(public), Wire 2=a, Wire 3=b, Wire 4=product
        // nPublic = 2 (including wire 0), but snarkjs reports nPublic = number of public outputs + public inputs
        assertTrue(pk.numPublic() >= 1, "Should have at least 1 public input");

        // Alpha, beta, delta should be non-infinity (from trusted setup)
        assertFalse(pk.alphaG1().isInfinity(), "alpha G1 should not be infinity");
        assertFalse(pk.betaG1().isInfinity(), "beta G1 should not be infinity");
        assertFalse(pk.deltaG1().isInfinity(), "delta G1 should not be infinity");
        assertFalse(pk.betaG2().isInfinity(), "beta G2 should not be infinity");
        assertFalse(pk.deltaG2().isInfinity(), "delta G2 should not be infinity");

        // Points arrays should be populated
        assertTrue(pk.pointsA().length > 0, "Should have A points");
        assertTrue(pk.pointsB1().length > 0, "Should have B1 points");
        assertTrue(pk.pointsB2().length > 0, "Should have B2 points");
        assertTrue(pk.pointsH().length > 0, "Should have H points");
    }

    @Test
    void importZkey_multiplier_pointsOnCurve() throws IOException {
        var pk = loadProvingKey();

        // Alpha should be on curve
        assertTrue(pk.alphaG1().isOnCurve() || pk.alphaG1().isInfinity(),
                "alpha G1 should be on curve");
        assertTrue(pk.betaG1().isOnCurve() || pk.betaG1().isInfinity(),
                "beta G1 should be on curve");
        assertTrue(pk.deltaG1().isOnCurve() || pk.deltaG1().isInfinity(),
                "delta G1 should be on curve");

        // Check G2 points are on twist curve
        assertTrue(pk.betaG2().isOnCurve() || pk.betaG2().isInfinity(),
                "beta G2 should be on twist curve");
        assertTrue(pk.deltaG2().isOnCurve() || pk.deltaG2().isInfinity(),
                "delta G2 should be on twist curve");

        // Check some A points
        for (int i = 0; i < Math.min(pk.pointsA().length, 5); i++) {
            assertTrue(pk.pointsA()[i].isOnCurve() || pk.pointsA()[i].isInfinity(),
                    "A[" + i + "] should be on curve");
        }

        // Check some H points
        for (int i = 0; i < Math.min(pk.pointsH().length, 4); i++) {
            assertTrue(pk.pointsH()[i].isOnCurve() || pk.pointsH()[i].isInfinity(),
                    "H[" + i + "] should be on curve");
        }
    }

    @Test
    void importZkey_multiplier_dimensionsCorrect() throws IOException {
        var pk = loadProvingKey();

        // Multiplier circuit has ~5 wires, 2 constraints → domainSize = 4
        assertTrue(pk.pointsA().length >= 4, "Should have at least 4 A points (nVars)");
        assertEquals(pk.pointsA().length, pk.pointsB1().length, "A and B1 should have same count");
        assertEquals(pk.pointsA().length, pk.pointsB2().length, "A and B2 should have same count");
        assertTrue(pk.pointsH().length >= 4, "H should have at least domainSize=4 points");
    }

    // --- Helper ---

    private Groth16ProvingKey loadProvingKey() throws IOException {
        InputStream is = getClass().getResourceAsStream(ZKEY_PATH);
        if (is == null) {
            // Try alternative path
            is = getClass().getResourceAsStream("/multiplier.zkey");
        }
        assertNotNull(is, "Test .zkey file not found at " + ZKEY_PATH);
        return ZkeyImporter.importZkey(is);
    }
}
