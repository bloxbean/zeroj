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
 * ADR-0031 M1 — the definitive ceremony round-trip over a <b>ZeroJ-authored</b> circuit:
 *
 * <pre>
 * ZeroJ R1CS ──R1csExporter──> .r1cs ──snarkjs──> powersoftau(bls12-381) → groth16 setup
 *     → zkey contribute → zkey verify(✓) ──ZkeyImporterBLS381──> ZeroJ prove → pairing verify(✓)
 * </pre>
 *
 * <p>Proves the exported file is accepted by real snarkjs tooling, that the ceremony transcript
 * verifies, and that the resulting MPC proving key produces proofs ZeroJ can generate and a
 * snarkjs-exported VK accepts — i.e. an external MPC ceremony key is a drop-in for ZeroJ's dev
 * setup. Skipped when snarkjs is not installed.</p>
 */
class R1csSnarkjsCeremonyRoundTripTest {

    private static final BigInteger FR = MontFr381.modulus();

    @Test
    void zerojR1cs_snarkjsCeremony_zerojProve_verifies(@TempDir Path dir) throws Exception {
        String snarkjs = findSnarkjs();
        assumeTrue(snarkjs != null, "snarkjs not found (install snarkjs or set -Dzeroj.snarkjs)");

        // 1. a ZeroJ R1CS: squaring chain, 1 public input (wire 1 = final value)
        int n = 64, numWires = n + 2, numPublic = 1;
        List<R1CSConstraint> cons = chain(n);
        BigInteger[] witness = witness(n);
        Path r1cs = dir.resolve("chain.r1cs");
        R1csExporter.export(cons, numWires, numPublic, r1cs);

        // 2. snarkjs accepts the exported file
        run(dir, snarkjs, "r1cs", "info", r1cs.toString());

        // 3. phase 1 (universal powers, BLS12-381) + phase 2 (circuit ceremony, 2 contributions)
        run(dir, snarkjs, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        run(dir, snarkjs, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau",
                "--name=zeroj-test-1", "-e=zeroj m1 entropy phase1");
        run(dir, snarkjs, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot_final.ptau");
        run(dir, snarkjs, "groth16", "setup", r1cs.toString(), "pot_final.ptau", "key0.zkey");
        run(dir, snarkjs, "zkey", "contribute", "key0.zkey", "key1.zkey",
                "--name=zeroj-test-2", "-e=zeroj m1 entropy phase2");

        // 4. the ceremony transcript verifies with snarkjs itself (the independent check)
        run(dir, snarkjs, "zkey", "verify", r1cs.toString(), "pot_final.ptau", "key1.zkey");
        run(dir, snarkjs, "zkey", "export", "verificationkey", "key1.zkey", "vk.json");

        // 5. import the MPC key into ZeroJ and prove (use the zkey's own constraints — snarkjs
        //    setup appends public-input binding rows)
        var zkeyData = ZkeyImporterBLS381.importZkeyFull(Files.readAllBytes(dir.resolve("key1.zkey")));
        var pk = zkeyData.provingKey();
        assertTrue(pk.alphaG1().isOnCurve() && pk.betaG2().isOnCurve() && pk.deltaG2().isOnCurve(),
                "imported MPC key points on curve");
        assertEquals(numWires, zkeyData.numWires(), "wire count preserved through the ceremony");
        assertEquals(numPublic, pk.numPublic(), "public count preserved");

        var proof = Groth16ProverBLS381.prove(pk, witness, zkeyData.constraints(), zkeyData.numWires());

        // 6. pairing-verify against the snarkjs-exported VK
        var vk = SnarkjsJsonCodec.parseVerificationKey(Files.readString(dir.resolve("vk.json")));
        G1Point vkX = parseG1(vk.ic().get(0));
        vkX = vkX.add(parseG1(vk.ic().get(1)).scalarMul(witness[1])); // public input = wire 1

        boolean verified = BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), parseG1(vk.vkAlpha1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), parseG2(vk.vkBeta2()), parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())});
        assertTrue(verified, "ZeroJ proof under the snarkjs MPC ceremony key MUST pairing-verify");

        System.out.println("[M1] ZeroJ r1cs -> snarkjs ceremony -> zkey verify OK -> ZeroJ prove -> pairing verify PASSED");
    }

    // ---- circuit ----

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

    // ---- snarkjs exec ----

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

    // ---- point conversion (mirrors Groth16BLS381ZkeyEndToEndTest) ----

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
