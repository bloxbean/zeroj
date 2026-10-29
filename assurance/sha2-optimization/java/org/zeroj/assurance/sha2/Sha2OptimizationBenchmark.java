package org.zeroj.assurance.sha2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.api.CircuitId;
import org.zeroj.api.CurveId;
import org.zeroj.api.ProofSystemId;
import org.zeroj.api.R1CSFlatIO;
import org.zeroj.api.VerificationMaterial;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.Variable;
import org.zeroj.circuit.lib.hash.Sha256;
import org.zeroj.circuit.lib.hash.Sha512;
import org.zeroj.codec.SnarkjsJsonCodec;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.groth16.ProverBackend;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.cryptoblst.BlstProverBackend;
import org.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryType;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/** Public fixtures and insecure development setup only; no production key material is retained. */
public final class Sha2OptimizationBenchmark {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final CurveId CURVE = CurveId.BLS12_381;
    private static String stage = "arguments";

    private Sha2OptimizationBenchmark() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 5) throw new IllegalArgumentException("SHA-256|SHA-512 bytes samples output pure-java|blst");
        String algorithm = args[0];
        int length = Integer.parseInt(args[1]);
        int samples = Integer.parseInt(args[2]);
        Path output = Path.of(args[3]);
        String backendName = args[4];
        require(List.of("SHA-256", "SHA-512").contains(algorithm), "Unsupported algorithm");
        require(List.of(32, 128, 1024).contains(length), "Unsupported profile length");
        require(samples >= 3 && samples <= 20, "Need 3..20 measured samples");
        require(List.of("pure-java", "blst").contains(backendName), "Unsupported backend");
        require(Boolean.getBoolean("zeroj.allowInsecureTrustedSetup"), "Development setup requires explicit opt-in");
        Files.createDirectory(output); // Never combine earlier results with a new key.
        Path temporary = Files.createTempDirectory("zeroj-sha2-benchmark-keys-");
        var report = new LinkedHashMap<String, Object>();
        report.put("algorithm", algorithm);
        report.put("messageBytes", length);
        report.put("backend", backendName);
        report.put("timestamp", Instant.now().toString());
        report.put("curve", "BLS12-381");
        report.put("setup", "INSECURE SINGLE-PARTY DEVELOPMENT ONLY");
        report.put("timingScope", "One first-call warmup then measured samples in a fresh JVM; compile/setup are single samples");
        report.put("javaRuntime", System.getProperty("java.runtime.version"));
        report.put("jvmArguments", ManagementFactory.getRuntimeMXBean().getInputArguments());
        report.put("processors", Runtime.getRuntime().availableProcessors());
        report.put("maxHeapBytes", Runtime.getRuntime().maxMemory());
        report.put("os", System.getProperty("os.name"));
        report.put("architecture", System.getProperty("os.arch"));
        report.put("initialLoadAverage", ManagementFactory.getOperatingSystemMXBean().getSystemLoadAverage());
        long[] gcBefore = gcCounters();
        try (var memory = new HeapSampler()) {
            try {
                run(algorithm, length, samples, backendName, output, temporary, report, memory);
                report.put("status", "passed");
            } catch (Throwable failure) {
                report.put("status", "failed");
                report.put("failedStage", stage);
                report.put("failure", failure.getClass().getName() + ": " + failure.getMessage());
                throw failure;
            } finally {
                report.put("sampledHeapPeakBytes", memory.peak());
                report.put("heapSamplingIntervalMs", 20);
                var poolPeaks = new LinkedHashMap<String, Long>();
                for (var pool : ManagementFactory.getMemoryPoolMXBeans())
                    if (pool.getType() == MemoryType.HEAP) poolPeaks.put(pool.getName(), pool.getPeakUsage().getUsed());
                report.put("heapPoolPeakUsedBytes", poolPeaks);
                report.put("memoryScope", "Sampled simultaneous heap usage can miss short peaks; pool peaks occur at different times and must not be summed as a measured peak. OS peak RSS is recorded separately by runner.");
                long[] after = gcCounters();
                report.put("gcCollections", after[0] - gcBefore[0]);
                report.put("gcTimeMs", after[1] - gcBefore[1]);
                report.put("finalLoadAverage", ManagementFactory.getOperatingSystemMXBean().getSystemLoadAverage());
                JSON.writerWithDefaultPrettyPrinter().writeValue(output.resolve("result.json").toFile(), report);
            }
        } finally {
            try (var paths = Files.walk(temporary)) {
                for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
            }
        }
    }

    private static void run(String algorithm, int length, int samples, String backendName,
                            Path output, Path temporary, Map<String, Object> report,
                            HeapSampler memory) throws Exception {
        byte[] message = new byte[length];
        for (int i = 0; i < length; i++) message[i] = (byte) i;
        byte[] digest = MessageDigest.getInstance(algorithm).digest(message);
        BigInteger[] publicInputs = limbs(digest);
        Map<String, List<BigInteger>> input = inputs(message, publicInputs);
        String name = algorithm.toLowerCase().replace("-", "") + "-" + length;
        ProverBackend backend = backendName.equals("pure-java") ? ProverBackend.PURE_JAVA : BlstProverBackend.create();

        stage = "circuit-build-and-compile";
        long start = System.nanoTime();
        var circuit = circuit(algorithm, length, publicInputs.length);
        var compiled = circuit.compileR1CSWithDiagnostics(CURVE);
        var system = compiled.system();
        report.put("compileMs", elapsed(start));
        report.put("constraints", system.numConstraints());
        report.put("wires", system.numWires());
        report.put("publicInputs", system.numPublicInputs());
        require(system.numPublicInputs() == publicInputs.length, "Unexpected public-input count");
        var flat = system.flat();
        report.put("terms", Map.of("a", flat.a().nnz(), "b", flat.b().nnz(), "c", flat.c().nnz(),
                "total", (long) flat.a().nnz() + flat.b().nnz() + flat.c().nnz()));
        report.put("pressureModeEntered", compiled.diagnostics().pressureModeEntered());
        memory.observe();

        stage = "relation-fingerprint";
        start = System.nanoTime();
        String relation = R1CSFlatIO.canonicalSha256(flat, system.numWires(), system.numPublicInputs());
        report.put("fingerprintMs", elapsed(start));
        report.put("r1csCanonicalSha256", relation);
        report.put("fingerprint", "c" + system.numConstraints() + "-w" + system.numWires()
                + "-p" + system.numPublicInputs() + "-r" + relation);

        stage = "first-witness";
        start = System.nanoTime();
        var witness = circuit.calculateWitness(input, CURVE);
        report.put("firstWitnessMs", elapsed(start));
        require(Arrays.equals(publicInputs, Arrays.copyOfRange(witness, 1, publicInputs.length + 1)), "Digest limbs mismatch");
        memory.observe();

        stage = "development-setup";
        start = System.nanoTime();
        // Only the fresh sampled tau scalar is used, not a four-power ceremony transcript.
        var tau = PowersOfTauBLS381.generate(4).tauScalar();
        Path keyPath = temporary.resolve("key");
        try (var keys = Groth16Keys.setupToStore(flat, system.numWires(), system.numPublicInputs(), tau, keyPath, true)) {
            report.put("setupMs", elapsed(start));
            report.put("qapDomain", keys.domain());
            report.put("keyStoreBytes", directoryBytes(keyPath));
            String vk = SnarkjsGroth16Json.verificationKeyJson(keys);
            String pub = SnarkjsGroth16Json.publicJson(publicInputs);
            var rows = new ArrayList<Map<String, Object>>();
            var proofHashes = new HashSet<String>();
            Groth16ProofBLS381 last = null;
            for (int i = 0; i <= samples; i++) {
                stage = "witness-sample-" + i;
                start = System.nanoTime();
                witness = circuit.calculateWitness(input, CURVE);
                double witnessMs = elapsed(start);
                stage = "prove-sample-" + i;
                start = System.nanoTime();
                last = keys.prove(backend, witness, system.constraints());
                double proveMs = elapsed(start);
                String proof = SnarkjsGroth16Json.proofJson(last);
                stage = "verify-sample-" + i;
                start = System.nanoTime();
                require(verify(name, vk, pub, proof), "Valid proof rejected");
                double verifyMs = elapsed(start);
                String proofHash = sha256(proof.getBytes(StandardCharsets.UTF_8));
                proofHashes.add(proofHash);
                rows.add(Map.of("sample", i, "warmup", i == 0, "witnessMs", witnessMs,
                        "proveMs", proveMs, "verifyMs", verifyMs, "proofSha256", proofHash));
                Files.writeString(output.resolve("proof-" + i + ".json"), proof);
                memory.observe();
                report.put("samples", rows);
                System.out.printf("%s/%s sample=%d witness=%.3fms prove=%.3fms verify=%.3fms%n",
                        name, backendName, i, witnessMs, proveMs, verifyMs);
            }
            require(proofHashes.size() == samples + 1, "Blinded proofs unexpectedly repeat");
            require(last != null, "No proof generated");
            String proof = SnarkjsGroth16Json.proofJson(last);
            stage = "negative-proof-checks";
            for (int i = 0; i < publicInputs.length; i++) {
                var changed = publicInputs.clone();
                changed[i] = changed[i].xor(BigInteger.ONE);
                String wrong = SnarkjsGroth16Json.publicJson(changed);
                require(!verify(name, vk, wrong, proof), "Changed digest limb accepted: " + i);
                Files.writeString(output.resolve("public-wrong-" + i + ".json"), wrong);
            }
            var negativeA = new AffineG1(last.a().x(), last.a().y().neg());
            require(negativeA.isOnCurve(), "Negated A must remain on curve");
            String invalid = SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(negativeA, last.b(), last.c()));
            require(!verify(name, vk, pub, invalid), "Negated proof A accepted");
            Files.writeString(output.resolve("verification_key.json"), vk);
            Files.writeString(output.resolve("public.json"), pub);
            Files.writeString(output.resolve("proof.json"), proof);
            Files.writeString(output.resolve("proof-negated-a.json"), invalid);
            Files.writeString(output.resolve("message.hex"), HexFormat.of().formatHex(message) + "\n");
            Files.writeString(output.resolve("digest.hex"), HexFormat.of().formatHex(digest) + "\n");
            report.put("randomizedProofsVerified", samples + 1);
            report.put("changedDigestLimbsRejected", publicInputs.length);
            report.put("canonicalNegatedARejected", true);
            report.put("verificationKeySha256", sha256(vk.getBytes(StandardCharsets.UTF_8)));
            stage = "complete";
        }
    }

    private static CircuitBuilder circuit(String algorithm, int length, int count) {
        var builder = CircuitBuilder.create("sha2-optimization-" + algorithm + "-" + length);
        for (int i = 0; i < count; i++) builder.publicVar("digest" + i);
        for (int i = 0; i < length; i++) builder.secretVar("byte" + i);
        return builder.define(api -> {
            var message = new Variable[length];
            for (int i = 0; i < length; i++) message[i] = api.var("byte" + i);
            var digest = algorithm.equals("SHA-256") ? Sha256.hashBytes(api, message) : Sha512.hashBytes(api, message);
            for (int limb = 0; limb < count; limb++) {
                Variable packed = api.constant(0);
                for (int j = 0; j < 16; j++) packed = api.add(api.mul(packed, api.constant(256)), digest[limb * 16 + j]);
                api.assertEqual(packed, api.var("digest" + limb));
            }
        });
    }

    private static Map<String, List<BigInteger>> inputs(byte[] message, BigInteger[] digest) {
        var input = new HashMap<String, List<BigInteger>>();
        for (int i = 0; i < digest.length; i++) input.put("digest" + i, List.of(digest[i]));
        for (int i = 0; i < message.length; i++) input.put("byte" + i, List.of(BigInteger.valueOf(message[i] & 255)));
        return input;
    }

    private static BigInteger[] limbs(byte[] digest) {
        var values = new BigInteger[digest.length / 16];
        for (int i = 0; i < values.length; i++) values[i] = new BigInteger(1, Arrays.copyOfRange(digest, i * 16, (i + 1) * 16));
        return values;
    }

    private static boolean verify(String name, String vk, String pub, String proof) {
        var id = new CircuitId(name);
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proof, vk, pub, id);
        var material = VerificationMaterial.of(vk.getBytes(StandardCharsets.UTF_8), ProofSystemId.GROTH16, CURVE, id);
        return new Groth16BLS12381PureJavaVerifier().verify(envelope, material).proofValid();
    }

    private static String sha256(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }

    private static double elapsed(long start) { return (System.nanoTime() - start) / 1e6; }

    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalStateException(message);
    }

    private static long directoryBytes(Path directory) throws IOException {
        long bytes = 0;
        try (var stream = Files.walk(directory)) {
            for (Path path : stream.filter(Files::isRegularFile).toList()) bytes += Files.size(path);
        }
        return bytes;
    }

    private static long[] gcCounters() {
        long count = 0, millis = 0;
        for (var gc : ManagementFactory.getGarbageCollectorMXBeans()) {
            count += Math.max(0, gc.getCollectionCount());
            millis += Math.max(0, gc.getCollectionTime());
        }
        return new long[]{count, millis};
    }

    private static final class HeapSampler implements AutoCloseable {
        private final AtomicLong maximum = new AtomicLong();
        private volatile boolean running = true;
        private final Thread worker;

        HeapSampler() {
            for (var pool : ManagementFactory.getMemoryPoolMXBeans()) pool.resetPeakUsage();
            worker = Thread.ofPlatform().daemon().name("sha2-benchmark-heap-sampler").start(() -> {
                while (running) {
                    observe();
                    try { Thread.sleep(20); } catch (InterruptedException interrupted) { break; }
                }
            });
        }

        void observe() { maximum.accumulateAndGet(ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed(), Math::max); }
        long peak() { observe(); return maximum.get(); }
        @Override public void close() throws InterruptedException { running = false; worker.interrupt(); worker.join(); }
    }
}
