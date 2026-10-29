package org.zeroj.it.sha2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.hash.Sha256;
import org.zeroj.circuit.lib.hash.Sha512;
import org.zeroj.circuit.r1cs.R1CSSerializer;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.groth16.ProverBackend;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0063: actual blinded Groth16 proofs of both SHA-2 gadgets on BLS12-381.
 *
 * <p>Run explicitly with {@code ./gradlew :zeroj-integration-tests:heavyTest --tests '*Sha2Groth16Test'}.
 * Uses fresh, flag-gated single-party development keys in JUnit temporary directories;
 * no production ceremony, constant-time implementation or application authorization is claimed.
 * All messages are deliberately public ascending-byte fixtures.
 *
 * <p>Timing is diagnostic only: one first proof followed by three further proofs with
 * the same open key. Compilation, witness generation, setup and verification have separate
 * timers. No wall-clock performance threshold is asserted. Each run writes a new result
 * directory under {@code build/sha2-proof-assurance}, so failed/repeated runs cannot combine
 * an earlier proof with a newly generated key.
 */
@Tag("heavy")
@Timeout(value = 10, unit = TimeUnit.MINUTES)
class Sha2Groth16Test {

    private static final int MESSAGE_BYTES = 32;
    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path keyDirectory;

    @Test
    void sha256ProofsBindEveryDigestLimb() throws Exception {
        proveAndCheck("SHA-256");
    }

    @Test
    void sha512ProofsBindEveryDigestLimb() throws Exception {
        proveAndCheck("SHA-512");
    }

    private void proveAndCheck(String algorithm) throws Exception {
        assertTrue(Boolean.getBoolean("zeroj.allowInsecureTrustedSetup"),
                "Use the explicit heavyTest task; development setup must remain opted in");
        String name = algorithm.toLowerCase().replace("-", "") + "-" + MESSAGE_BYTES;
        byte[] message = new byte[MESSAGE_BYTES];
        for (int i = 0; i < message.length; i++) message[i] = (byte) i;
        byte[] digest = MessageDigest.getInstance(algorithm).digest(message);
        BigInteger[] expectedPublic = digestLimbs(digest);
        Path outputRoot = Files.createDirectories(Path.of("build", "sha2-proof-assurance"));
        Path resultDirectory = Files.createTempDirectory(outputRoot, name + "-");

        var report = new LinkedHashMap<String, Object>();
        report.put("case", name);
        report.put("timestamp", Instant.now().toString());
        report.put("curve", "BLS12-381");
        report.put("backend", "pure-java");
        report.put("setup", "INSECURE SINGLE-PARTY DEVELOPMENT ONLY");
        report.put("timingScope", "Shared-host diagnostic: first call plus three warm samples; key stays open; no timing gate");
        report.put("javaRuntime", System.getProperty("java.runtime.version"));
        report.put("os", System.getProperty("os.name"));
        report.put("architecture", System.getProperty("os.arch"));
        report.put("processors", Runtime.getRuntime().availableProcessors());
        report.put("maxHeapBytes", Runtime.getRuntime().maxMemory());
        report.put("initialSystemLoadAverage", ManagementFactory.getOperatingSystemMXBean().getSystemLoadAverage());

        long started = System.nanoTime();
        CircuitBuilder circuit = circuit(algorithm, expectedPublic.length);
        var compiled = circuit.compileR1CS(CurveId.BLS12_381);
        var constraints = compiled.constraints();
        report.put("compileMs", elapsedMs(started));
        report.put("constraints", compiled.numConstraints());
        report.put("wires", compiled.numWires());
        report.put("publicInputs", compiled.numPublicInputs());
        assertEquals(expectedPublic.length, compiled.numPublicInputs());
        byte[] serialized = R1CSSerializer.serialize(compiled);
        report.put("r1csSha256", sha256(serialized));

        Map<String, List<BigInteger>> input = input(message, expectedPublic);
        started = System.nanoTime();
        BigInteger[] witness = circuit.calculateWitness(input, CurveId.BLS12_381);
        report.put("firstWitnessMs", elapsedMs(started));
        assertArrayEquals(expectedPublic, Arrays.copyOfRange(witness, 1, expectedPublic.length + 1));

        started = System.nanoTime();
        // Native development setup uses only the sampled tau scalar; this tiny generated
        // SRS is not represented as a ceremony for the much larger SHA relation.
        var tau = PowersOfTauBLS381.generate(4).tauScalar();
        try (var keys = Groth16Keys.setupToStore(compiled.flat(), compiled.numWires(),
                compiled.numPublicInputs(), tau, keyDirectory.resolve(name), true)) {
            report.put("setupMs", elapsedMs(started));
            report.put("qapDomain", keys.domain());
            report.put("keyStoreBytes", directoryBytes(keyDirectory.resolve(name)));
            String vkJson = SnarkjsGroth16Json.verificationKeyJson(keys);
            String publicJson = SnarkjsGroth16Json.publicJson(expectedPublic);
            var rows = new ArrayList<Map<String, Object>>();
            var proofIdentities = new HashSet<String>();
            Groth16ProofBLS381 lastProof = null;

            for (int iteration = 0; iteration < 4; iteration++) {
                started = System.nanoTime();
                witness = circuit.calculateWitness(input, CurveId.BLS12_381);
                double witnessMs = elapsedMs(started);
                started = System.nanoTime();
                lastProof = keys.prove(ProverBackend.PURE_JAVA, witness, constraints);
                double proveMs = elapsedMs(started);
                String proofJson = SnarkjsGroth16Json.proofJson(lastProof);
                started = System.nanoTime();
                assertTrue(verify(name, vkJson, publicJson, proofJson), "Every randomized proof must verify");
                double verifyMs = elapsedMs(started);
                String proofHash = sha256(proofJson.getBytes(StandardCharsets.UTF_8));
                proofIdentities.add(proofHash);
                rows.add(Map.of("iteration", iteration, "warmup", iteration == 0,
                        "witnessMs", witnessMs, "proveMs", proveMs, "verifyMs", verifyMs,
                        "proofSha256", proofHash));
                Files.writeString(resultDirectory.resolve("proof-" + iteration + ".json"), proofJson);
                System.out.printf("[ADR-0063] %s sample=%d witnessMs=%.3f proveMs=%.3f verifyMs=%.3f%n",
                        name, iteration, witnessMs, proveMs, verifyMs);
            }
            assertEquals(4, proofIdentities.size(), "Proof generation must retain random blinding");
            assertNotNull(lastProof);
            String proofJson = SnarkjsGroth16Json.proofJson(lastProof);
            for (int limb = 0; limb < expectedPublic.length; limb++) {
                BigInteger[] wrong = expectedPublic.clone();
                wrong[limb] = wrong[limb].xor(BigInteger.ONE);
                String wrongJson = SnarkjsGroth16Json.publicJson(wrong);
                assertFalse(verify(name, vkJson, wrongJson, proofJson), "Digest limb " + limb + " must be bound");
                Files.writeString(resultDirectory.resolve("public-wrong-" + limb + ".json"), wrongJson);
            }

            // Negating non-infinity A preserves a canonical, on-curve subgroup point,
            // but changes the pairing equation. This exercises proof validity, not parsing alone.
            var negativeA = new AffineG1(lastProof.a().x(), lastProof.a().y().neg());
            assertTrue(negativeA.isOnCurve());
            String wrongProofJson = SnarkjsGroth16Json.proofJson(
                    new Groth16ProofBLS381(negativeA, lastProof.b(), lastProof.c()));
            assertFalse(verify(name, vkJson, publicJson, wrongProofJson), "Canonical negated A must be rejected");

            Files.writeString(resultDirectory.resolve("verification_key.json"), vkJson);
            Files.writeString(resultDirectory.resolve("public.json"), publicJson);
            Files.writeString(resultDirectory.resolve("proof.json"), proofJson);
            Files.writeString(resultDirectory.resolve("proof-negated-a.json"), wrongProofJson);
            Files.writeString(resultDirectory.resolve("message.hex"), HexFormat.of().formatHex(message) + "\n");
            Files.writeString(resultDirectory.resolve("digest.hex"), HexFormat.of().formatHex(digest) + "\n");
            report.put("rows", rows);
            report.put("randomizedProofsVerified", 4);
            report.put("changedDigestLimbsRejected", expectedPublic.length);
            report.put("canonicalNegatedARejected", true);
            report.put("verificationKeySha256", sha256(vkJson.getBytes(StandardCharsets.UTF_8)));
            JSON.writerWithDefaultPrettyPrinter().writeValue(resultDirectory.resolve("result.json").toFile(), report);
            System.out.println("[ADR-0063] result=" + resultDirectory + " " + JSON.writeValueAsString(report));
        }
    }

    private static CircuitBuilder circuit(String algorithm, int limbs) {
        var builder = CircuitBuilder.create("sha2-groth16-" + algorithm);
        for (int i = 0; i < limbs; i++) builder.publicVar("digest" + i);
        for (int i = 0; i < MESSAGE_BYTES; i++) builder.secretVar("byte" + i);
        return builder.define(api -> {
            Variable[] message = new Variable[MESSAGE_BYTES];
            for (int i = 0; i < message.length; i++) message[i] = api.var("byte" + i);
            Variable[] digest = algorithm.equals("SHA-256")
                    ? Sha256.hashBytes(api, message) : Sha512.hashBytes(api, message);
            // Preserve every digest bit as consecutive big-endian 128-bit public limbs.
            for (int i = 0; i < limbs; i++) {
                Variable packed = api.constant(0);
                for (int j = 0; j < 16; j++)
                    packed = api.add(api.mul(packed, api.constant(256)), digest[16 * i + j]);
                api.assertEqual(packed, api.var("digest" + i));
            }
        });
    }

    private static BigInteger[] digestLimbs(byte[] digest) {
        BigInteger[] result = new BigInteger[digest.length / 16];
        for (int i = 0; i < result.length; i++)
            result[i] = new BigInteger(1, Arrays.copyOfRange(digest, i * 16, (i + 1) * 16));
        return result;
    }

    private static Map<String, List<BigInteger>> input(byte[] message, BigInteger[] digest) {
        var input = new HashMap<String, List<BigInteger>>();
        for (int i = 0; i < digest.length; i++) input.put("digest" + i, List.of(digest[i]));
        for (int i = 0; i < message.length; i++)
            input.put("byte" + i, List.of(BigInteger.valueOf(message[i] & 0xff)));
        return input;
    }

    private static boolean verify(String name, String vk, String publicInputs, String proof) {
        CircuitId id = new CircuitId(name);
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proof, vk, publicInputs, id);
        var material = VerificationMaterial.of(vk.getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, id);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }

    private static String sha256(byte[] value) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static double elapsedMs(long started) {
        return (System.nanoTime() - started) / 1e6;
    }

    private static long directoryBytes(Path directory) throws IOException {
        try (var files = Files.walk(directory)) {
            return files.filter(Files::isRegularFile).mapToLong(path -> {
                try {
                    return Files.size(path);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }).sum();
        }
    }
}
