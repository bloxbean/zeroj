package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
            var proof = Groth16Pipeline.prove(keys, cache, cc.fingerprint(),
                    () -> { compiles.incrementAndGet(); return compiled(cons, n + 2, 1); },
                    () -> FlatScalars.pack(w, w.length),
                    0, ProverBackend.PURE_JAVA);
            assertEquals(0, compiles.get(), "cache hit must never compile");
            assertTrue(pairingVerify(keys, proof, w[1]), "cache-hit proof must verify");
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
