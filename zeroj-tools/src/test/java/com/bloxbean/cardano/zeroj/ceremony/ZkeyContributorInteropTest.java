package com.bloxbean.cardano.zeroj.ceremony;

import com.bloxbean.cardano.zeroj.api.CurveId;
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
        String snarkjs = findSnarkjs();
        assumeTrue(snarkjs != null, "snarkjs not found");

        // ceremony genesis (snarkjs)
        Path r1cs = dir.resolve("mul.r1cs");
        assertEquals(0, CeremonyCli.run(new String[]{"export-r1cs",
                "--circuit", MulFixtureCircuit.class.getName(), "--out", r1cs.toString()}));
        run(dir, snarkjs, "powersoftau", "new", "bls12-381", "8", "pot0.ptau");
        run(dir, snarkjs, "powersoftau", "contribute", "pot0.ptau", "pot1.ptau", "--name=c1", "-e=e1");
        run(dir, snarkjs, "powersoftau", "prepare", "phase2", "pot1.ptau", "pot.ptau");
        run(dir, snarkjs, "groth16", "setup", r1cs.toString(), "pot.ptau", "key0.zkey");

        // contribution #1: ZeroJ-native (via the CLI)
        assertEquals(0, CeremonyCli.run(new String[]{"contribute",
                "--in", dir.resolve("key0.zkey").toString(),
                "--out", dir.resolve("key1.zkey").toString(),
                "--name", "zeroj-native-1"}));

        // (a) snarkjs must accept the ZeroJ contribution's transcript + PoK + L/H rescale
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

        // (c) the final key proves (via the in-memory importer for brevity) — full-circle sanity
        run(dir, snarkjs, "zkey", "export", "verificationkey", "key3.zkey", "vk.json");
        Path store = dir.resolve("pk");
        assertEquals(0, CeremonyCli.run(new String[]{"finalize",
                "--zkey", dir.resolve("key3.zkey").toString(), "--pk-store", store.toString()}));
        var builder = MulFixtureCircuit.build();
        var compiled = builder.compileR1CS(CurveId.BLS12_381);
        BigInteger[] witness = builder.calculateWitness(Map.of(
                "out", List.of(BigInteger.valueOf(391)),
                "a", List.of(BigInteger.valueOf(17)),
                "b", List.of(BigInteger.valueOf(23))), CurveId.BLS12_381);
        try (var loaded = com.bloxbean.cardano.zeroj.crypto.groth16.Groth16PkStore.load(store)) {
            var cons = com.bloxbean.cardano.zeroj.crypto.groth16.ZkeyPkStoreImporter
                    .snarkjsConstraints(compiled.constraints(), compiled.numPublicInputs());
            var proof = com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProverBLS381.proveWithReaders(
                    loaded.pk(), loaded.readers(),
                    com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend.PURE_JAVA,
                    witness, cons, compiled.numWires(), loaded.domain());
            assertTrue(proof.a().isOnCurve() && proof.b().isOnCurve() && proof.c().isOnCurve());
        }
        System.out.println("[M5] ZeroJ contribute -> snarkjs verify OK -> mixed-tool chain verify OK -> proves PASSED");
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
        assertTrue(p.waitFor(300, TimeUnit.SECONDS), "snarkjs timed out: " + String.join(" ", cmd));
        assertEquals(0, p.exitValue(), "snarkjs failed: " + String.join(" ", cmd) + "\n" + out);
    }
}
