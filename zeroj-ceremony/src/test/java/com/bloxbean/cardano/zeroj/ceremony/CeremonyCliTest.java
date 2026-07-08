package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.crypto.groth16.R1CSImporter;
import com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * ADR-0031 M4: the {@code zeroj-ceremony} CLI end to end — {@code export-r1cs} produces a valid
 * iden3 file from a reflectively-loaded circuit, and (gated on snarkjs) a full Option-A ceremony
 * driven through the CLI yields a proving-key store that proves and pairing-verifies.
 */
class CeremonyCliTest {

    @Test
    void exportR1cs_reflectiveLoad_producesValidFile(@TempDir Path dir) throws Exception {
        Path out = dir.resolve("mul.r1cs");
        int rc = CeremonyCli.run(new String[]{"export-r1cs",
                "--circuit", MulFixtureCircuit.class.getName().replaceAll("Circuit$", ""), // exercises the +Circuit suffix probe
                "--out", out.toString()});
        assertEquals(0, rc, "export-r1cs exit code");

        var data = R1CSImporter.importR1CS(new ByteArrayInputStream(Files.readAllBytes(out)));
        var compiled = MulFixtureCircuit.build().compileR1CS(CurveId.BLS12_381);
        assertEquals(compiled.numWires(), data.numWires(), "wires");
        assertEquals(compiled.numPublicInputs(), data.numPublic(), "publics");
        assertEquals(compiled.numConstraints(), data.numConstraints(), "constraints");
    }

    @Test
    void missingArgs_failCleanly() {
        assertThrows(IllegalArgumentException.class,
                () -> CeremonyCli.run(new String[]{"export-r1cs", "--out", "x.r1cs"}));
    }

    @Test
    void fullOptionA_ceremonyViaCli_provesAndVerifies(@TempDir Path dir) throws Exception {
        String snarkjs = findSnarkjs();
        assumeTrue(snarkjs != null, "snarkjs not found");

        // 1. export via CLI
        Path r1cs = dir.resolve("mul.r1cs");
        assertEquals(0, CeremonyCli.run(new String[]{"export-r1cs",
                "--circuit", MulFixtureCircuit.class.getName(), "--out", r1cs.toString()}));

        // 2. snarkjs ceremony (Option A runbook flow, small powers)
        run(dir, snarkjs, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        run(dir, snarkjs, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=c1", "-e=e1");
        run(dir, snarkjs, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot.ptau");
        run(dir, snarkjs, "groth16", "setup", r1cs.toString(), "pot.ptau", "key0.zkey");
        run(dir, snarkjs, "zkey", "contribute", "key0.zkey", "key1.zkey", "--name=c2", "-e=e2");
        run(dir, snarkjs, "zkey", "verify", r1cs.toString(), "pot.ptau", "key1.zkey");
        run(dir, snarkjs, "zkey", "export", "verificationkey", "key1.zkey", "vk.json");

        // 3. finalize via CLI
        Path store = dir.resolve("pk-store");
        assertEquals(0, CeremonyCli.run(new String[]{"finalize",
                "--zkey", dir.resolve("key1.zkey").toString(), "--pk-store", store.toString()}));

        // 4. prove from the store; verify against the snarkjs VK
        var builder = MulFixtureCircuit.build();
        var compiled = builder.compileR1CS(CurveId.BLS12_381);
        BigInteger[] witness = builder.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(33)),
                "a", List.of(BigInteger.valueOf(3)),
                "b", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);

        try (var loaded = Groth16PkStore.load(store)) {
            var cons = ZkeyPkStoreImporter.snarkjsConstraints(compiled.constraints(), compiled.numPublicInputs());
            var proof = Groth16ProverBLS381.proveWithReaders(loaded.pk(), loaded.readers(),
                    ProverBackend.PURE_JAVA, witness, cons, compiled.numWires(), loaded.domain());

            var vk = SnarkjsJsonCodec.parseVerificationKey(Files.readString(dir.resolve("vk.json")));
            G1Point vkX = parseG1(vk.ic().get(0)).add(parseG1(vk.ic().get(1)).scalarMul(witness[1]));
            boolean ok = BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1(proof.a()), parseG1(vk.vkAlpha1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                    new G2Point[]{toG2(proof.b()), parseG2(vk.vkBeta2()), parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())});
            assertTrue(ok, "CLI-driven Option-A ceremony key MUST produce verifying proofs");
        }
        System.out.println("[M4] CLI export-r1cs -> snarkjs ceremony -> CLI finalize -> prove -> verify PASSED");
    }

    // ---- helpers ----

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
