package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.R1CSFlatIO;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * {@link Groth16Pipeline} must reproduce the CLI orchestration exactly: setup emits a matching
 * {@code r1cs.bin}; a cache-hit prove never invokes the compile supplier; a cache-miss prove
 * compiles, caches, and the next prove hits; a bundle/circuit fingerprint mismatch fails fast.
 * All proofs pairing-verify.
 */
class Groth16PipelineTest {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allow() { System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true"); }

    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> c = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++) c.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        c.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return c;
    }

    private static BigInteger[] wit(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE; BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1]; return w;
    }

    private static Groth16Pipeline.Compiled compiled(List<R1CSConstraint> cons, int numWires, int numPublic) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return new Groth16Pipeline.Compiled(b.build(), cons.size(), numWires, numPublic);
    }

    @Test
    void setup_emitsCache_thenProveHitsWithoutCompiling(@TempDir Path dir) throws Exception {
        int n = 32;
        var cons = chain(n);
        var w = wit(n);
        var cc = compiled(cons, n + 2, 1);
        BigInteger tau = PowersOfTauBLS381.generate(7).tauScalar();

        var sr = Groth16Pipeline.setup(cc, tau, dir, true);
        assertNotNull(sr.gammaG2());
        Path cache = dir.resolve(Groth16Pipeline.R1CS_CACHE);
        assertTrue(Files.isRegularFile(cache), "setup must emit r1cs.bin");
        assertTrue(Groth16Pipeline.cacheMatches(cache, cc.fingerprint()));

        AtomicInteger compiles = new AtomicInteger();
        try (var keys = Groth16Keys.load(dir)) {
            assertEquals(cc.fingerprint(), keys.circuitFingerprint());
            var proof = Groth16Pipeline.prove(keys, cache, cc.fingerprint(),
                    () -> { compiles.incrementAndGet(); return compiled(cons, n + 2, 1); },
                    () -> FlatScalars.pack(w, w.length),
                    0, ProverBackend.PURE_JAVA);
            assertEquals(0, compiles.get(), "cache hit must never compile");
            assertTrue(pairingVerify(keys, proof, w[1]), "cache-hit proof must verify");

            byte[] corrupted = Files.readAllBytes(cache);
            corrupted[corrupted.length - 1] ^= 1;
            Files.write(cache, corrupted);
            assertFalse(Groth16Pipeline.cacheMatches(cache, cc.fingerprint()));
            var repairedProof = Groth16Pipeline.prove(keys, cache, cc.fingerprint(),
                    () -> { compiles.incrementAndGet(); return compiled(cons, n + 2, 1); },
                    () -> FlatScalars.pack(w, w.length),
                    0, ProverBackend.PURE_JAVA);
            assertEquals(1, compiles.get(), "a corrupt candidate cache must be recompiled once");
            assertTrue(pairingVerify(keys, repairedProof, w[1]));
            assertTrue(Groth16Pipeline.cacheMatches(cache, cc.fingerprint()),
                    "the fallback compile must atomically repair the persistent cache");
        }
    }

    @Test
    void proveMissCompilesAndCaches_secondProveHits(@TempDir Path dir) throws Exception {
        int n = 32;
        var cons = chain(n);
        var w = wit(n);
        var cc = compiled(cons, n + 2, 1);
        BigInteger tau = PowersOfTauBLS381.generate(7).tauScalar();

        // key store without a cache (simulates an imported/downloaded bundle)
        Groth16Keys.setupToStore(cc.flat(), n + 2, 1, tau, dir, true).close();
        Groth16PkStore.bindCircuitFingerprint(dir, cc.fingerprint());
        Path cache = dir.resolve(Groth16Pipeline.R1CS_CACHE);
        Files.deleteIfExists(cache);

        AtomicInteger compiles = new AtomicInteger();
        try (var keys = Groth16Keys.load(dir)) {
            var proof = Groth16Pipeline.prove(keys, cache, cc.fingerprint(),
                    () -> { compiles.incrementAndGet(); return compiled(cons, n + 2, 1); },
                    () -> FlatScalars.pack(w, w.length),
                    0, ProverBackend.PURE_JAVA);
            assertEquals(1, compiles.get(), "miss must compile once");
            assertTrue(Files.isRegularFile(cache), "miss must write the cache");
            assertTrue(pairingVerify(keys, proof, w[1]));

            var proof2 = Groth16Pipeline.prove(keys, cache, cc.fingerprint(),
                    () -> { compiles.incrementAndGet(); return compiled(cons, n + 2, 1); },
                    () -> FlatScalars.pack(w, w.length),
                    0, ProverBackend.PURE_JAVA);
            assertEquals(1, compiles.get(), "second prove must hit the cache");
            assertTrue(pairingVerify(keys, proof2, w[1]));

            // --no-cache semantics: null cache path always compiles, writes nothing
            var proof3 = Groth16Pipeline.prove(keys, null, cc.fingerprint(),
                    () -> { compiles.incrementAndGet(); return compiled(cons, n + 2, 1); },
                    () -> FlatScalars.pack(w, w.length),
                    0, ProverBackend.PURE_JAVA);
            assertEquals(2, compiles.get());
            assertTrue(pairingVerify(keys, proof3, w[1]));
        }
    }

    @Test
    void fingerprintMismatch_failsFast(@TempDir Path dir) throws Exception {
        int n = 16;
        var cons = chain(n);
        var w = wit(n);
        var cc = compiled(cons, n + 2, 1);
        BigInteger tau = PowersOfTauBLS381.generate(6).tauScalar();
        Groth16Keys.setupToStore(cc.flat(), n + 2, 1, tau, dir, true).close();
        Files.deleteIfExists(dir.resolve(Groth16Pipeline.R1CS_CACHE));

        try (var keys = Groth16Keys.load(dir)) {
            var ex = assertThrows(IllegalStateException.class, () ->
                    Groth16Pipeline.prove(keys, null, "c1-w4-p1",   // bundle claims another circuit
                            () -> compiled(cons, n + 2, 1),
                            () -> FlatScalars.pack(w, w.length),
                            0, ProverBackend.PURE_JAVA));
            assertTrue(ex.getMessage().contains("c1-w4-p1"));
        }
    }

    @Test
    void exactFingerprintBindsRelationNotOnlyDimensions_andUnboundKeysFailClosed(
            @TempDir Path dir) throws Exception {
        int n = 8;
        var original = chain(n);
        var altered = new ArrayList<>(original);
        altered.set(0, new R1CSConstraint(
                Map.of(2, BigInteger.ONE), Map.of(2, BigInteger.ONE),
                Map.of(3, BigInteger.TWO)));
        var first = compiled(original, n + 2, 1);
        var second = compiled(altered, n + 2, 1);
        assertEquals(Groth16Pipeline.fingerprint(n, n + 2, 1),
                first.fingerprint().substring(0, first.fingerprint().indexOf("-r")));
        assertNotEquals(first.fingerprint(), second.fingerprint());
        assertTrue(Groth16Pipeline.isExactFingerprint(first.fingerprint()));

        BigInteger tau = PowersOfTauBLS381.generate(5).tauScalar();
        Groth16Keys.setupToStore(first.flat(), n + 2, 1, tau, dir, true).close();
        try (var unbound = Groth16Keys.load(dir)) {
            IllegalStateException error = assertThrows(IllegalStateException.class,
                    () -> Groth16Pipeline.prove(
                            unbound, null, first.fingerprint(), () -> first,
                            () -> FlatScalars.pack(wit(n), n + 2),
                            0, ProverBackend.PURE_JAVA));
            assertTrue(error.getMessage().contains("unbound"));
        }

        Groth16PkStore.bindCircuitFingerprint(dir, first.fingerprint());
        try (var bound = Groth16Keys.load(dir)) {
            assertEquals(first.fingerprint(), bound.circuitFingerprint());
            assertThrows(IllegalStateException.class,
                    () -> Groth16Pipeline.prove(
                            bound, null, second.fingerprint(), () -> second,
                            () -> FlatScalars.pack(wit(n), n + 2),
                            0, ProverBackend.PURE_JAVA));
        }
        assertThrows(IllegalStateException.class,
                () -> Groth16PkStore.bindCircuitFingerprint(dir, second.fingerprint()));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16PkStore.bindCircuitFingerprint(dir, "c8-w10-p1-rnot-a-sha"));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16PkStore.bindCircuitFingerprint(
                        dir, "c999999999999999999999-w10-p1-r" + "00".repeat(32)));
        assertThrows(IllegalArgumentException.class,
                () -> Groth16PkStore.bindCircuitFingerprint(
                        dir, "c8-w10-p10-r" + "00".repeat(32)));
    }

    @Test
    void exactCacheBindingRejectsCopiedHeadersAndPayloadTampering(@TempDir Path dir)
            throws Exception {
        int n = 8;
        var original = chain(n);
        var altered = new ArrayList<>(original);
        altered.set(0, new R1CSConstraint(
                Map.of(2, BigInteger.ONE), Map.of(2, BigInteger.ONE),
                Map.of(3, BigInteger.TWO)));
        var first = compiled(original, n + 2, 1);
        var second = compiled(altered, n + 2, 1);
        Path cache = dir.resolve(Groth16Pipeline.R1CS_CACHE);

        R1CSFlatIO.write(first.flat(), first.fingerprint(), cache);
        assertTrue(Groth16Pipeline.cacheMatches(cache, first.fingerprint()));

        byte[] payloadTampered = Files.readAllBytes(cache);
        payloadTampered[payloadTampered.length - 1] ^= 1;
        Files.write(cache, payloadTampered);
        assertFalse(Groth16Pipeline.cacheMatches(cache, first.fingerprint()),
                "an exact cache hit must commit to the decoded relation, not only its header");

        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.write(second.flat(), first.fingerprint(), cache),
                "writers must not be able to label a foreign relation with another digest");

        R1CSFlatIO.write(second.flat(), second.fingerprint(), cache);
        byte[] copiedHeader = Files.readAllBytes(cache);
        byte[] firstHeader = first.fingerprint().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] secondHeader = second.fingerprint().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(firstHeader.length, secondHeader.length);
        assertArrayEquals(secondHeader,
                java.util.Arrays.copyOfRange(copiedHeader, 10, 10 + secondHeader.length));
        System.arraycopy(firstHeader, 0, copiedHeader, 10, firstHeader.length);
        Files.write(cache, copiedHeader);
        assertFalse(Groth16Pipeline.cacheMatches(cache, first.fingerprint()),
                "a copied exact header must not turn a foreign R1CS into a cache hit");

        byte[] fingerprint = first.fingerprint().getBytes(java.nio.charset.StandardCharsets.UTF_8);
        var hostile = java.nio.ByteBuffer.allocate(18 + fingerprint.length)
                .order(java.nio.ByteOrder.LITTLE_ENDIAN);
        hostile.putInt(0x5A4A5246).putInt(1).putShort((short) fingerprint.length)
                .put(fingerprint).putInt(first.numConstraints()).putInt(Integer.MAX_VALUE);
        Files.write(cache, hostile.array());
        assertFalse(Groth16Pipeline.cacheMatches(cache, first.fingerprint()),
                "hostile dimensions must be rejected before any attacker-sized allocation");
        assertNull(R1CSFlatIO.readIfMatches(cache, first.fingerprint()));

        String overflow = "c999999999999999999999-w10-p1-r" + "00".repeat(32);
        String invalidPublicCount = "c8-w10-p10-r" + "00".repeat(32);
        assertFalse(Groth16Pipeline.isExactFingerprint(overflow));
        assertFalse(Groth16Pipeline.isExactFingerprint(invalidPublicCount));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.write(first.flat(), overflow, cache));
        assertThrows(IllegalArgumentException.class,
                () -> R1CSFlatIO.write(first.flat(), invalidPublicCount, cache));
    }

    @Test
    void independentPythonCheckerAgreesAndRejectsPayloadTampering(@TempDir Path dir)
            throws Exception {
        Path script = Path.of(System.getProperty("user.dir"), "..", "zeroj-test-vectors",
                "scripts", "verify_zeroj_r1cs.py").toAbsolutePath().normalize();
        if (!Files.isRegularFile(script)) {
            script = Path.of(System.getProperty("user.dir"), "zeroj-test-vectors",
                    "scripts", "verify_zeroj_r1cs.py").toAbsolutePath().normalize();
        }
        Assumptions.assumeTrue(Files.isRegularFile(script), "independent checker source unavailable");
        try {
            Process probe = new ProcessBuilder("python3", "--version")
                    .redirectErrorStream(true).start();
            probe.getInputStream().readAllBytes();
            Assumptions.assumeTrue(probe.waitFor() == 0, "python3 unavailable");
        } catch (IOException unavailable) {
            Assumptions.assumeTrue(false, "python3 unavailable");
        }

        var compiled = compiled(chain(8), 10, 1);
        Path cache = dir.resolve("r1cs.bin");
        R1CSFlatIO.write(compiled.flat(), compiled.fingerprint(), cache);
        assertEquals(0, runIndependentChecker(script, cache, compiled.fingerprint()),
                "independent implementation must reproduce the Java canonical identity");

        byte[] tampered = Files.readAllBytes(cache);
        tampered[tampered.length - 1] ^= 1;
        Path hostile = dir.resolve("tampered-r1cs.bin");
        Files.write(hostile, tampered);
        assertNotEquals(0, runIndependentChecker(script, hostile, compiled.fingerprint()),
                "independent implementation must reject a relation mutation");
    }

    private static int runIndependentChecker(Path script, Path r1cs, String fingerprint)
            throws Exception {
        Process process = new ProcessBuilder(
                "python3", script.toString(), r1cs.toString(),
                "--expected-fingerprint", fingerprint, "--json")
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(),
                java.nio.charset.StandardCharsets.UTF_8);
        int exit = process.waitFor();
        if (exit != 0 && !r1cs.getFileName().toString().startsWith("tampered-")) {
            fail("independent R1CS checker failed: " + output);
        }
        return exit;
    }

    @Test
    void exactKeyManifestDimensionsAndPointCountsFailClosed(@TempDir Path dir) throws Exception {
        int n = 8;
        var compiled = compiled(chain(n), n + 2, 1);
        Groth16Pipeline.setup(compiled, PowersOfTauBLS381.generate(5).tauScalar(), dir, true);
        Path manifest = dir.resolve("manifest.properties");
        byte[] original = Files.readAllBytes(manifest);

        assertManifestMutationRejected(manifest, original,
                properties -> properties.setProperty("numB2", Integer.toString(n + 3)));
        assertManifestMutationRejected(manifest, original,
                properties -> properties.setProperty("numPublic", "2"));
        assertManifestMutationRejected(manifest, original,
                properties -> properties.setProperty("numIc", "3"));
        assertManifestMutationRejected(manifest, original,
                properties -> properties.setProperty("domain", "4"));
        assertManifestMutationRejected(manifest, original, properties ->
                properties.setProperty("circuitFingerprint",
                        "c" + n + "-w" + (n + 3) + "-p1-r" + compiled.r1csSha256()));

        Files.write(manifest, original);
        try (var keys = Groth16Keys.load(dir)) {
            assertEquals(compiled.fingerprint(), keys.circuitFingerprint());
        }
    }

    private static void assertManifestMutationRejected(
            Path manifest, byte[] original,
            java.util.function.Consumer<java.util.Properties> mutation) throws Exception {
        var properties = new java.util.Properties();
        properties.load(new java.io.ByteArrayInputStream(original));
        mutation.accept(properties);
        try (var output = Files.newOutputStream(manifest)) {
            properties.store(output, "tampered test manifest");
        }
        assertThrows(java.io.IOException.class, () -> Groth16Keys.load(manifest.getParent()));
        Files.write(manifest, original);
    }

    @Test
    void fingerprint_matchesCliFormat_andParsesBack() {
        String fp = Groth16Pipeline.fingerprint(19_075_097, 43_742_758, 28);
        assertEquals("c19075097-w43742758-p28", fp, "must stay byte-identical to CLI Bundle.fingerprint");
        var dims = Groth16Pipeline.parseFingerprint(fp);
        assertNotNull(dims);
        assertEquals(19_075_097, dims.numConstraints());
        assertEquals(43_742_758, dims.numWires());
        assertEquals(28, dims.numPublic());
        assertEquals(1 << 25, dims.domain(), "19M constraints -> 2^25 domain");
        assertNull(Groth16Pipeline.parseFingerprint("garbage"));
        assertNull(Groth16Pipeline.parseFingerprint(null));
        assertNull(Groth16Pipeline.parseFingerprint("c1-w4-p1-rbad"));
        assertNull(Groth16Pipeline.parseFingerprint("c1-w4-p1-r" + "00".repeat(32) + "tail"));
        assertNull(Groth16Pipeline.parseFingerprint(
                "c999999999999999999999-w4-p1-r" + "00".repeat(32)));
        assertNull(Groth16Pipeline.parseFingerprint("c1-w1-p1-r" + "00".repeat(32)));
    }

    @Test
    void heapEstimate_isLowerBoundOfMeasured19MFloor() {
        long est = Groth16Pipeline.estimateProvePhaseHeapBytes(43_742_758, 1 << 25);
        assertTrue(est > 5L << 30, "must account for the flat scalar buffers (>5 GB at 19M)");
        assertTrue(est <= 7L << 30, "must stay a LOWER bound of the measured 7 GB floor");
    }

    // ---- pairing verification (same as Groth16KeysTest) ----

    private static boolean pairingVerify(Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger pub) {
        G1Point vkX = toG1(keys.ic()[0]).add(toG1(keys.ic()[1]).scalarMul(pub));
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(keys.pk().alphaG1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(keys.pk().betaG2()), toG2(keys.gammaG2()), toG2(keys.pk().deltaG2())});
    }

    private static G1Point toG1(JacobianG1BLS381.AffineG1 p) {
        if (p.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }
}
