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
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The {@link Groth16Keys} facade must produce verifying proofs against every key home — heap
 * ({@code setupInMemory}), dense store, and sparse store ({@code setupToStore} + {@code load})
 * — with the same calls, and reject malformed witnesses uniformly. Pure delegation over the
 * ADR-0033/0035 entry points; the byte-level guarantees are covered by the differential tests.
 */
class Groth16KeysTest {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allow() { System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true"); }

    // Same squaring-chain circuit as Groth16PkStoreTest: wires [1, out, x, x^2, ...], 1 public.
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

    private static R1CSFlat flatOf(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    @Test
    void heapKeys_proveAndPairingVerify() {
        int n = 32;
        var cons = chain(n);
        var w = wit(n);
        BigInteger tau = PowersOfTauBLS381.generate(7).tauScalar();

        try (var keys = Groth16Keys.setupInMemory(cons, n + 2, 1, tau)) {
            assertEquals(n + 2, keys.numWires());
            var proof = keys.prove(w, cons);
            assertTrue(pairingVerify(keys, proof, w[1]), "heap-backed keys must verify");
            assertFalse(pairingVerify(keys, proof, w[1].add(BigInteger.ONE)),
                    "wrong public input must fail");
        }
    }

    @Test
    void storeKeys_sparseAndDense_proveLoadReprove(@TempDir Path tmp) throws Exception {
        int n = 32;
        var cons = chain(n);
        var flat = flatOf(cons);
        var w = wit(n);
        BigInteger tau = PowersOfTauBLS381.generate(7).tauScalar();

        for (boolean sparse : new boolean[]{true, false}) {
            Path dir = tmp.resolve(sparse ? "sparse" : "dense");

            // setup streamed to the store; the returned handle proves from it directly
            try (var keys = Groth16Keys.setupToStore(flat, n + 2, 1, tau, dir, sparse)) {
                assertEquals(n + 2, keys.numWires());
                var proof = keys.prove(w, cons);
                assertTrue(pairingVerify(keys, proof, w[1]), "fresh store keys (sparse=" + sparse + ")");

                // the flat/packed prove path against the same handle
                var proofFlat = keys.prove(ProverBackend.PURE_JAVA,
                        FlatScalars.pack(w, w.length), flat, 0);
                assertTrue(pairingVerify(keys, proofFlat, w[1]), "flat prove (sparse=" + sparse + ")");
            }

            // a later run: reopen the bundle and prove again
            try (var keys = Groth16Keys.load(dir)) {
                var proof = keys.prove(w, cons);
                assertTrue(pairingVerify(keys, proof, w[1]), "reloaded store keys (sparse=" + sparse + ")");
            }
        }
    }

    @Test
    void wrapExistingSetupResult_and_witnessValidation() {
        int n = 8;
        var cons = chain(n);
        var w = wit(n);
        BigInteger tau = PowersOfTauBLS381.generate(5).tauScalar();

        var sr = Groth16SetupBLS381.setup(cons, n + 2, 1, tau);
        try (var keys = Groth16Keys.of(sr)) {
            var proof = keys.prove(w, cons);
            assertTrue(pairingVerify(keys, proof, w[1]), "wrapped SetupResult must verify");

            assertThrows(IllegalArgumentException.class, () -> keys.prove(null, cons));
            assertThrows(IllegalArgumentException.class,
                    () -> keys.prove(new BigInteger[]{BigInteger.ONE}, cons), "wrong length");
            var badFirst = w.clone(); badFirst[0] = BigInteger.TWO;
            assertThrows(IllegalArgumentException.class, () -> keys.prove(badFirst, cons));
        }
    }

    // ---- Groth16 pairing verification from the handle's VK components ----

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
