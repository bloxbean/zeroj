package org.zeroj.crypto.groth16;

import org.zeroj.api.R1CSConstraint;
import org.zeroj.api.R1CSFlat;
import org.zeroj.api.R1CSValidation;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.field.MontFr381;
import org.zeroj.bls12381.pairing.BLS12381Pairing;
import org.zeroj.crypto.msm.FlatScalars;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * PR #56 review regression (ADR-0045): the public-wire binding check S1 is a <em>native setup</em>
 * invariant and must never gate proving under an imported snarkjs ceremony key. snarkjs binds
 * every public signal itself by appending {@code A={s:1}, B={}, C={}} rows, so a circuit whose
 * own relation has no constant term (the checked-in multiplier: {@code -a * b = -c}) is a valid
 * ceremony key; the pipeline receives the <em>original</em> relation plus
 * {@code snarkjsBindingRows} and must prove with the cache disabled, on a cache miss, and on a
 * cache hit.
 */
class Groth16PipelineCeremonyKeyTest {

    private static final String ZKEY = "/test-circuits/multiplier-bls381/multiplier.zkey";
    private static final String WTNS = "/test-circuits/multiplier-bls381/witness.wtns";
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void importedCeremonyKey_provesThroughPipeline_withoutCache_onMiss_andOnHit(@TempDir Path tmp) throws Exception {
        byte[] zkeyBytes = resource(ZKEY);
        var zkeyData = ZkeyImporterBLS381.importZkeyFull(zkeyBytes);
        int numPublic = zkeyData.provingKey().numPublic();
        int numWires = zkeyData.numWires();
        int bindingRows = numPublic + 1;
        int circuitRows = zkeyData.numConstraints() - bindingRows;
        assertTrue(circuitRows >= 1);
        List<R1CSConstraint> original = zkeyData.constraints().subList(0, circuitRows);

        // Premise of the regression: the original relation references no constant wire, so a
        // native setup of it is (correctly) rejected by S1 ...
        var s1 = assertThrows(IllegalArgumentException.class,
                () -> R1CSValidation.requirePublicWiresConstrained(original, numPublic, FR));
        assertTrue(s1.getMessage().contains("constant wire 0"), s1.getMessage());
        // ... while the ceremony key carries snarkjs's own binding rows right after the circuit rows.
        for (int s = 0; s <= numPublic; s++) {
            R1CSConstraint row = zkeyData.constraints().get(circuitRows + s);
            assertEquals(Map.of(s, ONE), row.a(), "snarkjs binding row for public signal " + s);
            assertTrue(row.b().isEmpty() && row.c().isEmpty());
        }

        Path zkeyFile = tmp.resolve("key.zkey");
        Files.write(zkeyFile, zkeyBytes);
        Path store = tmp.resolve("store");
        ZkeyPkStoreImporter.importToPkStore(zkeyFile, store);

        // Compiled must accept the original relation as-is (no S1 here).
        var cc = new Groth16Pipeline.Compiled(flatOf(original), circuitRows, numWires, numPublic);
        BigInteger[] witness = ZkeyImporterBLS381.importWtns(new ByteArrayInputStream(resource(WTNS)));
        assertEquals(numWires, witness.length);
        FlatScalars w = FlatScalars.pack(witness, witness.length);
        BigInteger[] pub = Arrays.copyOfRange(witness, 1, 1 + numPublic);

        // (a) cache disabled, unbound key
        try (var keys = Groth16Keys.load(store)) {
            var proof = Groth16Pipeline.prove(keys, null, null, () -> cc, () -> w, bindingRows, ProverBackend.PURE_JAVA);
            assertTrue(pairingVerify(keys, proof, pub), "cache disabled");
        }

        // (b) cache miss: the pipeline compiles, writes r1cs.bin, and proves
        Path cache = tmp.resolve(Groth16Pipeline.R1CS_CACHE);
        try (var keys = Groth16Keys.load(store)) {
            var proof = Groth16Pipeline.prove(keys, cache, null, () -> cc, () -> w, bindingRows, ProverBackend.PURE_JAVA);
            assertTrue(pairingVerify(keys, proof, pub), "cache miss");
        }
        assertTrue(Files.exists(cache), "cache must have been written on the miss");
        assertTrue(Groth16Pipeline.cacheMatches(cache, cc.fingerprint()));

        // (c) cache hit on a bundle bound to the exact fingerprint: no recompilation
        Groth16PkStore.bindCircuitFingerprint(store, cc.fingerprint());
        try (var keys = Groth16Keys.load(store)) {
            assertEquals(cc.fingerprint(), keys.circuitFingerprint());
            var proof = Groth16Pipeline.prove(keys, cache, cc.fingerprint(),
                    () -> { throw new AssertionError("a cache hit must not recompile"); },
                    () -> w, bindingRows, ProverBackend.PURE_JAVA);
            assertTrue(pairingVerify(keys, proof, pub), "cache hit");
            BigInteger[] wrong = pub.clone();
            wrong[0] = wrong[0].add(ONE).mod(FR);
            assertFalse(pairingVerify(keys, proof, wrong), "wrong public input must fail");
        }
    }

    // ---- helpers ----

    private static byte[] resource(String path) throws IOException {
        try (var in = Groth16PipelineCeremonyKeyTest.class.getResourceAsStream(path)) {
            if (in == null) throw new IOException("missing test resource " + path);
            return in.readAllBytes();
        }
    }

    private static R1CSFlat flatOf(List<R1CSConstraint> cons) {
        var b = R1CSFlat.builder();
        for (var c : cons) b.add(c.a(), c.b(), c.c());
        return b.build();
    }

    private static boolean pairingVerify(Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger[] pub) {
        G1Point vkX = toG1(keys.ic()[0]);
        for (int i = 0; i < pub.length; i++) vkX = vkX.add(toG1(keys.ic()[i + 1]).scalarMul(pub[i]));
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
