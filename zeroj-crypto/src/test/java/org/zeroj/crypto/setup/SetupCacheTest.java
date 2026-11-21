package org.zeroj.crypto.setup;

import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.R1CSFlat;
import org.zeroj.api.TrustedSetupPolicy;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16Pipeline;
import org.zeroj.crypto.groth16.Groth16ProvingKeyBLS381;
import org.zeroj.crypto.kzg.KZGCommitmentBLS381;
import org.zeroj.crypto.msm.FlatScalars;
import org.zeroj.crypto.plonk.PlonKProvingKeyBLS381;
import org.zeroj.crypto.plonk.PlonKSetupBLS381;
import org.zeroj.crypto.plonk.PtauImporterBLS381;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

        assertThrows(IOException.class, () -> Groth16SetupCache.loadBls12381Srs(path));
    }

    @Test
    void insecureTrustedSetupRequiresExplicitOptInAcrossAllSites() throws Exception {
        Assumptions.assumeFalse(
                "true".equalsIgnoreCase(System.getenv(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_ENV)),
                "Environment variable overrides system property");

        // Prepare valid fixtures while opt-in is enabled.
        var srs = PowersOfTauBLS381.generate(4);
        Path srsWithTau = tempDir.resolve("srs-with-tau.insecure");
        Groth16SetupCache.saveBls12381InsecureDevSrsWithTau(srs, srsWithTau);
        var constraints = List.of(
                new R1CSConstraint(Map.of(2, BigInteger.ONE), Map.of(3, BigInteger.ONE), Map.of(1, BigInteger.ONE)),
                new R1CSConstraint(Map.of(0, BigInteger.ONE), Map.of(0, BigInteger.ONE), Map.of(0, BigInteger.ONE)));
        var flatBuilder = R1CSFlat.builder();
        for (var c : constraints) flatBuilder.add(c.a(), c.b(), c.c());
        var flat = flatBuilder.build();
        var compiled = new Groth16Pipeline.Compiled(flat, constraints.size(), 4, 1);

        try {
            System.clearProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY);
            assertThrows(IllegalStateException.class, () -> PowersOfTauBLS381.generate(4));
            assertThrows(IllegalStateException.class,
                    () -> Groth16SetupBLS381.setup(constraints, 4, 1, srs.tauScalar()));
            assertThrows(IllegalStateException.class,
                    () -> Groth16SetupBLS381.setupToStore(flat, 4, 1, srs.tauScalar(), tempDir.resolve("store-1")));
            assertThrows(IllegalStateException.class,
                    () -> Groth16SetupCache.saveBls12381InsecureDevSrsWithTau(srs, tempDir.resolve("srs-2.insecure")));
            assertThrows(IllegalStateException.class,
                    () -> Groth16SetupCache.loadBls12381Srs(srsWithTau));
            Path pipelineDir = tempDir.resolve("pipeline-denied");
            assertThrows(IllegalStateException.class,
                    () -> Groth16Pipeline.setup(compiled, srs.tauScalar(), pipelineDir, false));
            assertFalse(Files.exists(pipelineDir),
                    "Groth16Pipeline.setup must fail before creating output directory");
            assertThrows(IllegalStateException.class,
                    () -> Groth16Keys.setupInMemory(constraints, 4, 1, srs.tauScalar()));
        } finally {
            restoreProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, previousInsecureTrustedSetup);
        }
    }

    @Test
    void setupAndKzgHardeningRejectsInvalidPowerNonBijectiveSigmaAndNonZeroRemainder() {
        assertThrows(IllegalArgumentException.class, () -> PowersOfTauBLS381.generate(29));

        // KZG syntheticDivision must reject a claimed evaluation with non-zero remainder.
        MontFr381[] poly = {MontFr381.fromLong(3), MontFr381.fromLong(2), MontFr381.fromLong(1)}; // x^2 + 2x + 3
        MontFr381 z = MontFr381.fromLong(5); // p(5) = 25 + 10 + 3 = 38
        assertThrows(IllegalArgumentException.class,
                () -> KZGCommitmentBLS381.syntheticDivision(poly, z, MontFr381.fromLong(39)));
        var q = KZGCommitmentBLS381.syntheticDivision(poly, z, MontFr381.fromLong(38));
        assertEquals(2, q.length);

        // PlonKSetupBLS381 must reject non-bijective sigma permutations.
        var srs = PowersOfTauBLS381.generate(4);
        BigInteger[][] selectors = {
                {BigInteger.ONE, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO},
                {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO}
        };
        int[] dupSigmaA = {0, 0}; // duplicate target 0
        int[] sigmaB = {2, 3};
        int[] sigmaC = {4, 5};
        assertThrows(IllegalArgumentException.class,
                () -> PlonKSetupBLS381.setup(2, 0, selectors, dupSigmaA, sigmaB, sigmaC, 4, srs));
    }

    @Test
    void groth16SetupCacheRoundTripsBls381() throws Exception {
        var constraints = List.of(
                new R1CSConstraint(
                        Map.of(2, BigInteger.ONE),
                        Map.of(3, BigInteger.ONE),
                        Map.of(1, BigInteger.ONE)),
                // 1 * 1 = 1 binds the constant wire (ADR-0045 S1)
                new R1CSConstraint(
                        Map.of(0, BigInteger.ONE),
                        Map.of(0, BigInteger.ONE),
                        Map.of(0, BigInteger.ONE))
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

    @Test
    void partialPrefixSrsCacheRoundTripsAndSupportsPlonkSetup() throws Exception {
        var full = PowersOfTauBLS381.generate(4);

        // Partial 14-point prefix (e.g. domainSize=8 + 6) of a power-4 ceremony round-trips cleanly.
        var partial14 = new PtauImporterBLS381.SRS(
                Arrays.copyOf(full.tauG1(), 14), full.tauG2(), full.power(), null);
        Path path14 = tempDir.resolve("srs-partial-14.bin");
        Groth16SetupCache.saveBls12381Srs(partial14, path14);
        var loaded14 = Groth16SetupCache.loadBls12381Srs(path14);
        assertEquals(4, loaded14.power());
        assertEquals(14, loaded14.tauG1().length);
        assertArrayEquals(partial14.tauG1(), loaded14.tauG1());
        assertArrayEquals(partial14.tauG2(), loaded14.tauG2());

        // Partial 16-point prefix (< 2^(power+1) = 32) round-trips and feeds PlonKSetupBLS381.setup.
        var partial16 = new PtauImporterBLS381.SRS(
                Arrays.copyOf(full.tauG1(), 16), full.tauG2(), full.power(), null);
        Path path16 = tempDir.resolve("srs-partial-16.bin");
        Groth16SetupCache.saveBls12381Srs(partial16, path16);
        var loaded16 = Groth16SetupCache.loadBls12381Srs(path16);
        assertEquals(16, loaded16.tauG1().length);

        var circuit = CircuitBuilder.create("plonk-partial-srs")
                .publicVar("c").secretVar("a").secretVar("b")
                .define(api -> api.assertEqual(api.mul(api.var("a"), api.var("b")), api.var("c")));
        var plonk = circuit.compilePlonK(CurveId.BLS12_381);
        BigInteger[][] gateSelectors = new BigInteger[plonk.numGates()][5];
        for (int i = 0; i < plonk.numGates(); i++) {
            var row = plonk.gateRows().get(i);
            gateSelectors[i] = new BigInteger[]{row.qL(), row.qR(), row.qO(), row.qM(), row.qC()};
        }
        var pk = PlonKSetupBLS381.setup(plonk.numGates(), plonk.numPublicInputs(), gateSelectors,
                plonk.sigmaA(), plonk.sigmaB(), plonk.sigmaC(), plonk.numWires(), loaded16);
        assertNotNull(pk);
    }

    @Test
    void srsCacheRejectsTauMismatchAndNonMinimalScalarEncoding() throws Exception {
        var srs = PowersOfTauBLS381.generate(4);
        BigInteger wrongTau = srs.tauScalar().add(BigInteger.ONE).mod(MontFr381.modulus());
        var mismatchedSrs = new PtauImporterBLS381.SRS(srs.tauG1(), srs.tauG2(), srs.power(), wrongTau);

        assertThrows(IOException.class,
                () -> Groth16SetupCache.saveBls12381InsecureDevSrsWithTau(mismatchedSrs, tempDir.resolve("bad-save.bin")));

        Path forgedPath = tempDir.resolve("forged-tau.bin");
        SetupCacheIO.writeCacheFile(forgedPath, SetupCacheIO.TYPE_BLS12381_SRS, out -> {
            out.writeInt(srs.power());
            SetupCacheIO.writeG1Array(out, srs.tauG1());
            SetupCacheIO.writeG2Array(out, srs.tauG2());
            out.writeBoolean(true);
            SetupCacheIO.writeScalar(out, wrongTau, "tau scalar");
        });
        assertThrows(IOException.class, () -> Groth16SetupCache.loadBls12381Srs(forgedPath));

        // Non-minimal big-endian two's-complement scalar encoding (extra leading zero byte on 1).
        ByteArrayOutputStream nonMinimal = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(nonMinimal)) {
            out.writeInt(2);
            out.write(new byte[]{0x00, 0x01});
        }
        assertThrows(IOException.class, () -> SetupCacheIO.readScalar(
                new DataInputStream(new ByteArrayInputStream(nonMinimal.toByteArray())), "test"));
    }

    @Test
    void groth16SetupAndPipelineRejectDegenerateTauAndFlatScalarsWrapRejectsBadBounds() {
        var constraints = List.of(
                new R1CSConstraint(Map.of(2, BigInteger.ONE), Map.of(3, BigInteger.ONE), Map.of(1, BigInteger.ONE)),
                new R1CSConstraint(Map.of(0, BigInteger.ONE), Map.of(0, BigInteger.ONE), Map.of(0, BigInteger.ONE)));
        var flatBuilder = R1CSFlat.builder();
        for (var c : constraints) flatBuilder.add(c.a(), c.b(), c.c());
        var flat = flatBuilder.build();
        var compiled = new Groth16Pipeline.Compiled(flat, constraints.size(), 4, 1);

        // tau == 0 and tau == 1 (a 2N-th root of unity) must both be rejected before directory creation.
        for (BigInteger badTau : List.of(BigInteger.ZERO, BigInteger.ONE)) {
            assertThrows(IllegalArgumentException.class,
                    () -> Groth16SetupBLS381.setup(constraints, 4, 1, badTau));
            Path dir = tempDir.resolve("bad-tau-" + badTau);
            assertThrows(IllegalArgumentException.class,
                    () -> Groth16Pipeline.setup(compiled, badTau, dir, false));
            assertFalse(Files.exists(dir), "Groth16Pipeline.setup must fail before creating directory for bad tau");
        }

        // FlatScalars.wrap bounds validation.
        assertThrows(IllegalArgumentException.class, () -> FlatScalars.wrap(new long[4], -1));
        assertThrows(IllegalArgumentException.class, () -> FlatScalars.wrap(new long[3], 1));
        assertThrows(IllegalArgumentException.class, () -> FlatScalars.wrap(new long[4], 2));
        assertEquals(1, FlatScalars.wrap(new long[4], 1).count());
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
