package org.zeroj.ceremony;

import org.zeroj.api.CurveId;
import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;
import org.zeroj.bls12381.pairing.BLS12381Pairing;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16PkStore;
import org.zeroj.crypto.groth16.Groth16ProverBLS381;
import org.zeroj.crypto.groth16.ProverBackend;
import org.zeroj.crypto.groth16.ZkeyPkStoreImporter;
import org.zeroj.crypto.testsupport.SnarkjsCliLocator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
 * ADR-0031 M5 — the definitive Option-B interop check: a <b>ZeroJ-native</b> contribution spliced
 * into a real snarkjs ceremony must (a) be accepted by {@code snarkjs zkey verify} (which
 * re-derives the PoK challenge from the transcript — any hash/encoding mismatch fails here),
 * (b) serve as a valid base for a further <b>snarkjs</b> contribution on top (mixed-tool
 * transcript), and (c) yield a key that proves and verifies. Skipped when snarkjs is absent.
 */
class ZkeyContributorInteropTest {

    @Test
    void zerojContribution_verifiedBySnarkjs_mixedTranscript(@TempDir Path dir) throws Exception {
        String snarkjs = requireSnarkjs();

        // ceremony genesis (snarkjs)
        Path r1cs = dir.resolve("mul.r1cs");
        assertEquals(0, CeremonyCli.run(new String[]{"export-r1cs",
                "--circuit", MulFixtureCircuit.class.getName(), "--out", r1cs.toString()}));
        run(dir, snarkjs, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        run(dir, snarkjs, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=c1", "-e=e1");
        run(dir, snarkjs, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot.ptau");
        run(dir, snarkjs, "groth16", "setup", r1cs.toString(), "pot.ptau", "key0.zkey");

        // contribution #1: ZeroJ-native (via the CLI) with a UTF-16 boundary name matching snarkjs 0.7.6
        String boundaryName = "a".repeat(63) + "\uD83D\uDE00";
        assertEquals(0, CeremonyCli.run(new String[]{"contribute",
                "--in", dir.resolve("key0.zkey").toString(),
                "--out", dir.resolve("key1.zkey").toString(),
                "--name", boundaryName}));

        // (a) snarkjs must accept the ZeroJ contribution's transcript + PoK + L/H rescale + UTF-8 name
        run(dir, snarkjs, "zkey", "verify", r1cs.toString(), "pot.ptau", "key1.zkey");

        // (b) a snarkjs contribution must stack on top of ours (mixed-tool chain), then verify
        run(dir, snarkjs, "zkey", "contribute", "key1.zkey", "key2.zkey", "--name=snarkjs-2", "-e=e2");
        run(dir, snarkjs, "zkey", "verify", r1cs.toString(), "pot.ptau", "key2.zkey");

        // and a second ZeroJ contribution on top of that, verified again
        assertEquals(0, CeremonyCli.run(new String[]{"contribute",
                "--in", dir.resolve("key2.zkey").toString(),
                "--out", dir.resolve("key3.zkey").toString(),
                "--name", "zeroj-native-3"}));
        run(dir, snarkjs, "zkey", "verify", r1cs.toString(), "pot.ptau", "key3.zkey");

        // (c) the final key proves and pairing-verifies against the snarkjs-exported VK
        run(dir, snarkjs, "zkey", "export", "verificationkey", "key3.zkey", "vk.json");
        Path store = dir.resolve("pk");
        assertEquals(0, CeremonyCli.run(new String[]{"finalize", "--allow-unpinned",
                "--zkey", dir.resolve("key3.zkey").toString(), "--pk-store", store.toString()}));
        var builder = MulFixtureCircuit.build();
        var compiled = builder.compileR1CS(CurveId.BLS12_381);
        BigInteger[] witness = builder.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(391)),
                "a", List.of(BigInteger.valueOf(17)),
                "b", List.of(BigInteger.valueOf(23))), CurveId.BLS12_381);
        try (var loaded = Groth16PkStore.load(store)) {
            var cons = ZkeyPkStoreImporter
                    .snarkjsConstraints(compiled.constraints(), compiled.numPublicInputs());
            var proof = Groth16ProverBLS381.proveWithReaders(
                    loaded.pk(), loaded.readers(),
                    ProverBackend.PURE_JAVA,
                    witness, cons, compiled.numWires(), loaded.domain());
            assertTrue(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve());

            var vk = SnarkjsJsonCodec.parseVerificationKey(Files.readString(dir.resolve("vk.json")));
            G1Point vkX = parseG1(vk.ic().get(0)).add(parseG1(vk.ic().get(1)).scalarMul(witness[1]));
            boolean ok = BLS12381Pairing.pairingCheck(
                    new G1Point[]{toG1(proof.a()), parseG1(vk.vkAlpha1()).negate(), vkX.negate(), toG1(proof.c()).negate()},
                    new G2Point[]{toG2(proof.b()), parseG2(vk.vkBeta2()), parseG2(vk.vkGamma2()), parseG2(vk.vkDelta2())});
            assertTrue(ok, "Mixed-tool ceremony proof MUST pairing-verify against final snarkjs VK");
        }
        System.out.println("[M5] ZeroJ contribute -> snarkjs verify OK -> mixed-tool chain verify OK -> proves & verifies PASSED");
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

    private static String requireSnarkjs() {
        var res = SnarkjsCliLocator.resolvePinned();
        if (!res.isReady()) {
            if (SnarkjsCliLocator.isRequired()) {
                fail(res.reason() + " — required by -PrequireSnarkjs");
            }
            assumeTrue(false, res.reason() + " — skipping");
        }
        return res.binary();
    }

    private static void run(Path dir, String... cmd) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).directory(dir.toFile()).redirectErrorStream(true).start();
        String out = new String(p.getInputStream().readAllBytes());
        assertTrue(p.waitFor(300, TimeUnit.SECONDS), "snarkjs timed out: " + String.join(" ", cmd));
        assertEquals(0, p.exitValue(), "snarkjs failed: " + String.join(" ", cmd) + "\n" + out);
    }
}
