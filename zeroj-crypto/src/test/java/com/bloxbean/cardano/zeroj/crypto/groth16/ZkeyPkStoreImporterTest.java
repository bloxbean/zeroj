package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0031 M2 — the streaming {@link ZkeyPkStoreImporter} must convert a real snarkjs ceremony
 * {@code .zkey} into a {@link Groth16PkStore} that (a) is <b>bit-identical</b> to what the strict
 * in-memory importer parses, (b) proves under {@link ZkeyPkStoreImporter#snarkjsConstraints}
 * (whose binding-row synthesis is asserted against the zkey's own coefficient section), and
 * (c) pairing-verifies against the snarkjs-exported VK. Skipped when snarkjs is absent.
 */
class ZkeyPkStoreImporterTest {

    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void ceremonyZkey_streamImport_provesFromStore(@TempDir Path dir) throws Exception {
        String snarkjs = findSnarkjs();
        assumeTrue(snarkjs != null, "snarkjs not found");

        // snarkjs ceremony over an exported ZeroJ circuit (M1 flow)
        int n = 64, numWires = n + 2, numPublic = 1;
        List<R1CSConstraint> cons = chain(n);
        BigInteger[] witness = witness(n);
        Path r1cs = dir.resolve("chain.r1cs");
        R1csExporter.export(cons, numWires, numPublic, r1cs);
        run(dir, snarkjs, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        run(dir, snarkjs, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=c1", "-e=e1");
        run(dir, snarkjs, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot.ptau");
        run(dir, snarkjs, "groth16", "setup", r1cs.toString(), "pot.ptau", "key0.zkey");
        run(dir, snarkjs, "zkey", "contribute", "key0.zkey", "key1.zkey", "--name=c2", "-e=e2");
        run(dir, snarkjs, "zkey", "export", "verificationkey", "key1.zkey", "vk.json");

        // 1. streaming import → PkStore
        Path store = dir.resolve("pk-store");
        var dims = ZkeyPkStoreImporter.importToPkStore(dir.resolve("key1.zkey"), store);
        assertEquals(numWires, dims.numWires());
        assertEquals(numPublic, dims.numPublic());

        // 2. differential vs the strict in-memory importer — flat G1 arrays bit-identical
        var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(dir.resolve("key1.zkey")));
        var memPk = zkeyData.provingKey();
        try (var loaded = Groth16PkStore.load(store)) {
            long[] buf = new long[12], ref = new long[12];
            for (int i = 0; i < numWires; i++) {
                loaded.readers().a().readInto(i, buf);
                System.arraycopy(memPk.pointsA(), i * 12, ref, 0, 12);
                assertArrayEquals(ref, buf, "pointsA[" + i + "]");
            }
            assertEquals(memPk.alphaG1().xBigInt(), loaded.pk().alphaG1().xBigInt(), "alpha");
            assertEquals(memPk.deltaG2().x().reBigInt(), loaded.pk().deltaG2().x().reBigInt(), "deltaG2");
            for (int i = 0; i < numWires; i++) {
                assertEquals(memPk.pointsB2()[i].x().reBigInt(), loaded.pk().pointsB2()[i].x().reBigInt(),
                        "pointsB2[" + i + "].x.re");
            }

            // 3. the binding-row synthesis matches the zkey's own coefficient section.
            //    Note: the zkey stores ONLY the A and B matrices — Groth16 provers (incl. ZeroJ's
            //    computeH) derive C = A·B pointwise on satisfied rows, so C is never persisted.
            var synth = ZkeyPkStoreImporter.snarkjsConstraints(cons, numPublic);
            for (int i = 0; i < synth.size(); i++) {
                assertEquals(synth.get(i).a(), zkeyData.constraints().get(i).a(), "A row " + i);
                assertEquals(synth.get(i).b(), zkeyData.constraints().get(i).b(), "B row " + i);
            }
            for (int i = synth.size(); i < zkeyData.constraints().size(); i++) {
                assertTrue(zkeyData.constraints().get(i).a().isEmpty()
                        && zkeyData.constraints().get(i).b().isEmpty(), "padding row " + i + " empty");
            }

            // 4. prove from the store (mmap'd) with synthesized constraints; verify vs snarkjs VK
            var proof = Groth16ProverBLS381.proveWithReaders(loaded.pk(), loaded.readers(),
                    ProverBackend.PURE_JAVA, witness, synth, numWires, loaded.domain());
            var vk = SnarkjsJsonCodec.parseVerificationKey(Files.readString(dir.resolve("vk.json")));
            G1Point vkX = parseG1(vk.ic().get(0)).add(parseG1(vk.ic().get(1)).scalarMul(witness[1]));
            boolean ok = BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1(proof.a()), parseG1(vk.vkAlpha1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                    new G2Point[]{toG2(proof.b()), parseG2(vk.vkBeta2()), parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())});
            assertTrue(ok, "proof from stream-imported ceremony key MUST pairing-verify");
        }
        System.out.println("[M2] ceremony zkey -> stream import -> PkStore -> prove -> pairing verify PASSED");
    }

    // ---- helpers (as in the M1 test) ----

    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> c = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            c.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        c.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return c;
    }

    private static BigInteger[] witness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1];
        return w;
    }

    private static String findSnarkjs() {
        String prop = System.getProperty("zeroj.snarkjs");
        for (String cand : new String[]{prop,
                System.getProperty("user.home") + "/.npm-global/bin/snarkjs",
                "/usr/local/bin/snarkjs", "/opt/homebrew/bin/snarkjs"}) {
            if (cand != null && Files.isExecutable(Path.of(cand))) return cand;
        }
        return null;
    }

    private static void run(Path dir, String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        assertTrue(p.waitFor(180, TimeUnit.SECONDS), "snarkjs timed out: " + String.join(" ", cmd));
        assertEquals(0, p.exitValue(), "snarkjs failed: " + String.join(" ", cmd) + "\n" + out);
    }

    private static G1Point toG1(JacobianG1BLS381.AffineG1 p) {
        return p.isInfinity() ? G1Point.INFINITY : new G1Point(Fp.of(p.xBigInt()), Fp.of(p.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 p) {
        if (p.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(p.x().reBigInt()), Fp.of(p.x().imBigInt())),
                Fp2.of(Fp.of(p.y().reBigInt()), Fp.of(p.y().imBigInt())));
    }

    private static G1Point parseG1(List<BigInteger> c) { return new G1Point(Fp.of(c.get(0)), Fp.of(c.get(1))); }

    private static G2Point parseG2(List<List<BigInteger>> c) {
        return new G2Point(
                Fp2.of(Fp.of(c.get(0).get(0)), Fp.of(c.get(0).get(1))),
                Fp2.of(Fp.of(c.get(1).get(0)), Fp.of(c.get(1).get(1))));
    }
}
