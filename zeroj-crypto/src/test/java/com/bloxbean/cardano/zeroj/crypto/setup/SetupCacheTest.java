package com.bloxbean.cardano.zeroj.crypto.setup;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import com.bloxbean.cardano.zeroj.crypto.plonk.PlonKSetupBLS381;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SetupCacheTest {

    @TempDir
    Path tempDir;
    private String previousInsecureTrustedSetup;

    @BeforeEach
    void enableDevSetup() {
        previousInsecureTrustedSetup = System.getProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY);
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    @AfterEach
    void restoreDevSetup() {
        restoreProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, previousInsecureTrustedSetup);
    }

    @Test
    void srsCacheRoundTripsCanonicalBls381MontgomeryLimbs() throws Exception {
        var srs = PowersOfTauBLS381.generate(4);
        Path path = tempDir.resolve("srs.bin");

        Groth16SetupCache.saveBls12381Srs(srs, path);
        var loaded = Groth16SetupCache.loadBls12381Srs(path);

        assertEquals(srs.power(), loaded.power());
        assertNull(loaded.tauScalar());
        assertArrayEquals(srs.tauG1(), loaded.tauG1());
        assertArrayEquals(srs.tauG2(), loaded.tauG2());
    }

    @Test
    void insecureDevSrsCacheRoundTripsTauOnlyThroughExplicitMethod() throws Exception {
        var srs = PowersOfTauBLS381.generate(4);
        Path path = tempDir.resolve("srs.insecure");

        Groth16SetupCache.saveBls12381InsecureDevSrsWithTau(srs, path);
        var loaded = Groth16SetupCache.loadBls12381Srs(path);

        assertEquals(srs.tauScalar(), loaded.tauScalar());
    }

    @Test
    void tamperedSrsCacheIsRejected() throws Exception {
        var srs = PowersOfTauBLS381.generate(4);
        Path path = tempDir.resolve("srs.bin");
        Groth16SetupCache.saveBls12381Srs(srs, path);

        byte[] bytes = Files.readAllBytes(path);
        bytes[bytes.length - 1] ^= 0x01;
        Files.write(path, bytes);

        assertThrows(java.io.IOException.class, () -> Groth16SetupCache.loadBls12381Srs(path));
    }

    @Test
    void insecureTrustedSetupRequiresExplicitOptIn() {
        try {
            System.clearProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY);
            if (!"true".equalsIgnoreCase(System.getenv(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_ENV))) {
                assertThrows(IllegalStateException.class, () -> PowersOfTauBLS381.generate(4));
            }
        } finally {
            restoreProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, previousInsecureTrustedSetup);
        }
    }

    @Test
    void groth16SetupCacheRoundTripsBls381() throws Exception {
        var constraints = List.of(
                new R1CSConstraint(
                        Map.of(2, BigInteger.ONE),
                        Map.of(3, BigInteger.ONE),
                        Map.of(1, BigInteger.ONE))
        );
        var srs = PowersOfTauBLS381.generate(4);
        var setup = Groth16SetupBLS381.setup(constraints, 4, 1, srs.tauScalar());
        Path path = tempDir.resolve("groth16-setup.bin");

        Groth16SetupCache.saveBls12381Setup(setup, path);
        var loaded = Groth16SetupCache.loadBls12381Setup(path);

        assertGroth16SetupEquals(setup, loaded);
    }

    @Test
    void plonkProvingKeyCacheRoundTripsBls381() throws Exception {
        var circuit = CircuitBuilder.create("plonk-cache-test")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        int numGates = plonk.numGates();
        BigInteger[][] gateSelectors = new BigInteger[numGates][5];
        for (int i = 0; i < numGates; i++) {
            var row = plonk.gateRows().get(i);
            gateSelectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }
        var srs = PowersOfTauBLS381.generate(4);
        var pk = PlonKSetupBLS381.setup(numGates, plonk.numPublicInputs(), gateSelectors,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), srs);
        Path path = tempDir.resolve("plonk-pk.bin");

        PlonkSetupCache.saveBls12381ProvingKey(pk, path);
        var loaded = PlonkSetupCache.loadBls12381ProvingKey(path);

        assertPlonkProvingKeyEquals(pk, loaded);
    }

    private static void assertGroth16SetupEquals(
            Groth16SetupBLS381.SetupResult expected,
            Groth16SetupBLS381.SetupResult actual) {
        assertGroth16ProvingKeyEquals(expected.provingKey(), actual.provingKey());
        assertEquals(expected.gammaG2(), actual.gammaG2());
        assertArrayEquals(expected.ic(), actual.ic());
    }

    private static void assertGroth16ProvingKeyEquals(
            Groth16ProvingKeyBLS381 expected,
            Groth16ProvingKeyBLS381 actual) {
        assertEquals(expected.alphaG1(), actual.alphaG1());
        assertEquals(expected.betaG1(), actual.betaG1());
        assertEquals(expected.betaG2(), actual.betaG2());
        assertEquals(expected.deltaG1(), actual.deltaG1());
        assertEquals(expected.deltaG2(), actual.deltaG2());
        assertEquals(expected.numPublic(), actual.numPublic());
        assertArrayEquals(expected.pointsA(), actual.pointsA());
        assertArrayEquals(expected.pointsB1(), actual.pointsB1());
        assertArrayEquals(expected.pointsB2(), actual.pointsB2());
        assertArrayEquals(expected.pointsH(), actual.pointsH());
        assertArrayEquals(expected.pointsL(), actual.pointsL());
    }

    private static void assertPlonkProvingKeyEquals(PlonKProvingKeyBLS381 expected, PlonKProvingKeyBLS381 actual) {
        assertEquals(expected.domainSize(), actual.domainSize());
        assertEquals(expected.nPublic(), actual.nPublic());
        assertEquals(expected.nConstraints(), actual.nConstraints());
        assertEquals(expected.k1(), actual.k1());
        assertEquals(expected.k2(), actual.k2());
        assertEquals(expected.omega(), actual.omega());
        assertArrayEquals(expected.ql(), actual.ql());
        assertArrayEquals(expected.qr(), actual.qr());
        assertArrayEquals(expected.qm(), actual.qm());
        assertArrayEquals(expected.qo(), actual.qo());
        assertArrayEquals(expected.qc(), actual.qc());
        assertArrayEquals(expected.s1(), actual.s1());
        assertArrayEquals(expected.s2(), actual.s2());
        assertArrayEquals(expected.s3(), actual.s3());
        assertArrayEquals(expected.srsG1(), actual.srsG1());
        assertArrayEquals(expected.srsG1Lagrange(), actual.srsG1Lagrange());
        assertEquals(expected.x2(), actual.x2());
        assertEquals(expected.qmCommit(), actual.qmCommit());
        assertEquals(expected.qlCommit(), actual.qlCommit());
        assertEquals(expected.qrCommit(), actual.qrCommit());
        assertEquals(expected.qoCommit(), actual.qoCommit());
        assertEquals(expected.qcCommit(), actual.qcCommit());
        assertEquals(expected.s1Commit(), actual.s1Commit());
        assertEquals(expected.s2Commit(), actual.s2Commit());
        assertEquals(expected.s3Commit(), actual.s3Commit());
    }

    private static void restoreProperty(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }
}
