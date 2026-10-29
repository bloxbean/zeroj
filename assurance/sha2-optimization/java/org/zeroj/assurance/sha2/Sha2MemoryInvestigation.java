package org.zeroj.assurance.sha2;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.zeroj.api.CurveId;
import org.zeroj.api.R1CSFlat;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.crypto.groth16.Groth16Pipeline;
import org.zeroj.crypto.groth16.Groth16ProofBLS381;
import org.zeroj.crypto.groth16.ProverBackend;
import org.zeroj.crypto.msm.FlatScalars;
import org.zeroj.crypto.setup.PowersOfTauBLS381;
import org.zeroj.crypto.snarkjs.SnarkjsGroth16Json;
import org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.HeapSampler;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.management.ManagementFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.circuit;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.directoryBytes;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.elapsed;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.inputs;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.limbs;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.require;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.sha256;
import static org.zeroj.assurance.sha2.Sha2OptimizationBenchmark.verify;

/** Public-fixture diagnostics only. Production crypto and relation construction are reused unchanged. */
public final class Sha2MemoryInvestigation {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final CurveId CURVE = CurveId.BLS12_381;
    // Public regression identities from the original 16 KiB document-size campaign.
    private static final Map<String, String> DOCUMENT_FINGERPRINTS = Map.of(
            "SHA-256", "c6934995-w26447846-p2-r328cdfc92ab5c5b0b588fa36b655b46543d2f8d3745b75703a4d32605659824c",
            "SHA-512", "c8799049-w33477000-p4-rba1c59c5121ada411e7d2df3ffcd87cbb6ebea3761dde0a59e57546dcdd4e26b");
    private static String stage = "arguments";
    // Explicit root only for the controlled retained-set experiment, never for pipeline timing.
    private static volatile Retained retained;
    private static final class Retained {
        CircuitBuilder graph;
        R1CSFlat constraints;
        BigInteger[] witness;
    }

    public static void main(String[] args) throws Exception {
        require(args.length == 5, "algorithm bytes measured-samples output pipeline|live-set");
        String algorithm = args[0], mode = args[4];
        int length = Integer.parseInt(args[1]), samples = Integer.parseInt(args[2]);
        require(List.of("SHA-256", "SHA-512").contains(algorithm), "Unsupported algorithm");
        require(List.of(32, 16384).contains(length), "Use small control or 16 KiB boundary");
        require(samples >= 1 && samples <= 3, "Need 1..3 measured samples");
        require(List.of("pipeline", "live-set").contains(mode), "Unsupported mode");
        require(Boolean.getBoolean("zeroj.allowInsecureTrustedSetup"), "Development opt-in required");
        Path output = Path.of(args[3]);
        Files.createDirectory(output);
        Path temporary = Path.of(System.getProperty("sha2.benchmark.tempKeys"));
        Files.createDirectory(temporary);
        var report = new LinkedHashMap<String, Object>();
        report.put("algorithm", algorithm); report.put("messageBytes", length);
        report.put("backend", "pure-java"); report.put("experiment", mode);
        report.put("setup", "INSECURE SINGLE-PARTY DEVELOPMENT ONLY");
        report.put("curve", "BLS12-381"); report.put("timestamp", Instant.now().toString());
        report.put("pid", ProcessHandle.current().pid());
        report.put("javaRuntime", System.getProperty("java.runtime.version"));
        report.put("jvmArguments", ManagementFactory.getRuntimeMXBean().getInputArguments());
        report.put("maxHeapBytes", Runtime.getRuntime().maxMemory());
        report.put("processors", Runtime.getRuntime().availableProcessors());
        try (var memory = new HeapSampler()) {
            try {
                phase("effective-controls", output, report, memory);
                require(Runtime.getRuntime().maxMemory() == Long.getLong("sha2.benchmark.expectedHeapBytes", -1L), "Heap override");
                require(Runtime.getRuntime().availableProcessors() == Integer.getInteger("sha2.benchmark.expectedProcessors", -1), "CPU override");
                byte[] message = new byte[length];
                for (int i = 0; i < length; i++) message[i] = (byte) i;
                byte[] digest = MessageDigest.getInstance(algorithm).digest(message);
                BigInteger[] publicInputs = limbs(digest);
                var input = inputs(message, publicInputs);
                if (mode.equals("live-set")) liveSet(algorithm, length, input, publicInputs, output, report, memory);
                else pipeline(algorithm, length, samples, message, digest, publicInputs, input, output, temporary, report, memory);
                report.put("status", "passed");
            } catch (Throwable failure) {
                report.put("status", "failed"); report.put("failedStage", stage);
                report.put("failure", failure.getClass().getName() + ": " + failure.getMessage());
                throw failure;
            } finally {
                report.put("sampledHeapPeakBytes", memory.peak());
                report.put("heapSamplingIntervalMs", 20);
                write(output.resolve("result.json"), report);
            }
        } finally {
            retained = null;
            if (Files.exists(temporary)) {
                try (var paths = Files.walk(temporary)) {
                    for (Path p : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(p);
                }
            }
        }
    }

    private static void liveSet(String algorithm, int length, Map<String, List<BigInteger>> input,
                                BigInteger[] publicInputs, Path output, Map<String, Object> report,
                                HeapSampler memory) throws Exception {
        phase("controlled-retained-set-build", output, report, memory);
        prepareRetained(algorithm, length, input, publicInputs, report);
        snapshot("graph-csr-boxed-witness", output, report, memory);
        retained.graph = null;
        snapshot("csr-boxed-witness", output, report, memory);
        retained.witness = null;
        snapshot("csr-only", output, report, memory);
        retained.constraints = null;
        snapshot("released", output, report, memory);
        report.put("diagnosticOnly", true);
        report.put("timingScope", "Controlled roots; each jcmd live histogram requests full GC. Not benchmark latency.");
    }

    private static void prepareRetained(String algorithm, int length, Map<String, List<BigInteger>> input,
                                        BigInteger[] publicInputs, Map<String, Object> report) {
        var state = new Retained();
        state.graph = circuit(algorithm, length, publicInputs.length);
        var compiled = state.graph.compileR1CSWithDiagnostics(CURVE);
        var system = compiled.system();
        state.constraints = system.flat();
        dimensions(new Groth16Pipeline.Compiled(state.constraints, system.numConstraints(), system.numWires(), system.numPublicInputs()), report);
        state.witness = state.graph.calculateWitness(input, CURVE);
        require(Arrays.equals(publicInputs, Arrays.copyOfRange(state.witness, 1, publicInputs.length + 1)), "Digest mismatch");
        retained = state;
    }

    private static void snapshot(String name, Path output, Map<String, Object> report, HeapSampler memory) throws Exception {
        phase("live-heap-" + name, output, report, memory);
        report.put("snapshot", name); report.put("phaseState", "awaiting-histogram");
        checkpoint(output, report, memory);
        long deadline = System.nanoTime() + 120_000_000_000L;
        while (!Files.exists(output.resolve("continue-" + name))) {
            require(System.nanoTime() < deadline, "Histogram controller timed out: " + name);
            Thread.sleep(100);
        }
        report.remove("snapshot"); report.put("phaseState", "completed");
        checkpoint(output, report, memory);
    }

    private static void pipeline(String algorithm, int length, int samples, byte[] message, byte[] digest,
                                 BigInteger[] publicInputs, Map<String, List<BigInteger>> input, Path output,
                                 Path temporary, Map<String, Object> report, HeapSampler memory) throws Exception {
        report.put("warmupSamples", 1); report.put("measuredSamples", samples);
        report.put("timingScope", "Fresh JVM; one warmup; Witness/packing/proof/verify clocks exclude checkpoint IO; encompassing setup includes its callback checkpoint. Pipeline total includes checkpoints, witness, packing, cache validation, proving and arena close. One measured sample establishes feasibility, not stable latency.");
        Path keyDir = temporary.resolve("keys");
        // Neither the circuit graph nor the compiled CSR is returned by this helper.
        setup(algorithm, length, publicInputs.length, keyDir, output, report, memory);
        String fingerprint = (String) report.get("fingerprint");
        String name = algorithm.toLowerCase().replace("-", "") + "-" + length;
        try (var keys = Groth16Keys.load(keyDir)) {
            require(fingerprint.equals(keys.circuitFingerprint()), "Exact key binding mismatch");
            report.put("qapDomain", keys.domain());
            String vk = SnarkjsGroth16Json.verificationKeyJson(keys);
            String pub = SnarkjsGroth16Json.publicJson(publicInputs);
            Files.writeString(output.resolve("verification_key.json"), vk);
            Files.writeString(output.resolve("public.json"), pub);
            Files.writeString(output.resolve("message.hex"), HexFormat.of().formatHex(message) + "\n");
            Files.writeString(output.resolve("digest.hex"), HexFormat.of().formatHex(digest) + "\n");
            var rows = new ArrayList<Map<String, Object>>();
            var hashes = new HashSet<String>();
            Groth16ProofBLS381 last = null;
            for (int i = 0; i <= samples; i++) {
                final int sampleNumber = i;
                phase("pipeline-sample-" + i, output, report, memory);
                var durations = new LinkedHashMap<String, Object>();
                var clocks = new long[1];
                var mapped = new boolean[1];
                long totalStart = System.nanoTime();
                last = Groth16Pipeline.prove(keys, keyDir.resolve(Groth16Pipeline.R1CS_CACHE), fingerprint,
                        () -> { throw new IllegalStateException("Expected verified cache hit; compile supplier invoked"); },
                        () -> {
                            phaseUnchecked("witness-build-sample-" + sampleNumber, output, report, memory);
                            long start = System.nanoTime();
                            BigInteger[] boxed = witness(algorithm, length, input, publicInputs);
                            double buildMs = elapsed(start);
                            durations.put("witnessBuildAndEvaluateMs", buildMs);
                            phaseUnchecked("packing-sample-" + sampleNumber, output, report, memory);
                            long packStart = System.nanoTime();
                            FlatScalars packed = FlatScalars.packConsuming(boxed, boxed.length);
                            double packMs = elapsed(packStart);
                            durations.put("packingMs", packMs);
                            durations.put("witnessMs", buildMs + packMs);
                            phaseUnchecked("cache-validate-sample-" + sampleNumber, output, report, memory);
                            return packed;
                        }, 0, ProverBackend.PURE_JAVA, new Groth16Pipeline.Progress() {
                            @Override public void constraintsMapped(int count, double seconds) {
                                mapped[0] = true; durations.put("cacheMapAndValidateMs", seconds * 1000);
                            }
                            @Override public void constraintCacheUnreadable() {
                                throw new IllegalStateException("Expected intact exact-bound constraint cache");
                            }
                            @Override public void proveStarted() {
                                phaseUnchecked("prove-sample-" + sampleNumber, output, report, memory);
                                clocks[0] = System.nanoTime();
                            }
                        });
                double proofMs = elapsed(clocks[0]), pipelineMs = elapsed(totalStart);
                require(mapped[0] && clocks[0] != 0, "Did not exercise mapped cache path");
                phase("proof-serialization-sample-" + i, output, report, memory);
                String proof = SnarkjsGroth16Json.proofJson(last);
                phase("verify-sample-" + i, output, report, memory);
                long verifyStart = System.nanoTime();
                require(verify(name, vk, pub, proof), "Valid proof rejected");
                durations.put("verifyMs", elapsed(verifyStart));
                durations.put("sample", i); durations.put("warmup", i == 0);
                durations.put("proveMs", proofMs); durations.put("pipelineMs", pipelineMs);
                durations.put("cacheHit", true);
                String hash = sha256(proof.getBytes(StandardCharsets.UTF_8));
                durations.put("proofSha256", hash); hashes.add(hash);
                Files.writeString(output.resolve("proof-" + i + ".json"), proof);
                rows.add(durations); report.put("samples", rows);
                report.put("phaseState", "completed");
                checkpoint(output, report, memory);
                System.out.printf("%s sample=%d pipeline=%.3fms proof=%.3fms%n", name, i, pipelineMs, proofMs);
            }
            require(last != null && hashes.size() == samples + 1, "Randomized proofs unexpectedly repeat");
            phase("negative-proof-checks", output, report, memory);
            String proof = SnarkjsGroth16Json.proofJson(last);
            for (int i = 0; i < publicInputs.length; i++) {
                var changed = publicInputs.clone(); changed[i] = changed[i].xor(BigInteger.ONE);
                String wrong = SnarkjsGroth16Json.publicJson(changed);
                require(!verify(name, vk, wrong, proof), "Changed digest accepted");
                Files.writeString(output.resolve("public-wrong-" + i + ".json"), wrong);
            }
            var negativeA = new AffineG1(last.a().x(), last.a().y().neg());
            require(negativeA.isOnCurve(), "Negated A must stay on curve");
            String bad = SnarkjsGroth16Json.proofJson(new Groth16ProofBLS381(negativeA, last.b(), last.c()));
            require(!verify(name, vk, pub, bad), "Invalid proof accepted");
            Files.writeString(output.resolve("proof.json"), proof);
            Files.writeString(output.resolve("proof-negated-a.json"), bad);
            report.put("randomizedProofsVerified", samples + 1);
            report.put("changedDigestLimbsRejected", publicInputs.length);
            report.put("canonicalNegatedARejected", true);
            report.put("phaseState", "completed"); checkpoint(output, report, memory);
        }
    }

    private static void setup(String algorithm, int length, int publicCount, Path keys, Path output,
                              Map<String, Object> report, HeapSampler memory) throws Exception {
        phase("compile-with-graph-release", output, report, memory);
        long compileStart = System.nanoTime();
        Groth16Pipeline.Compiled compiled = compile(algorithm, length, publicCount);
        report.put("compileAndFingerprintMs", elapsed(compileStart));
        dimensions(compiled, report);
        phase("constraint-cache-write", output, report, memory);
        long start = System.nanoTime();
        Groth16Pipeline.setup(compiled, PowersOfTauBLS381.generate(4).tauScalar(), keys, true,
                new Groth16Pipeline.Progress() {
                    @Override public void constraintCacheWritten(Path path, double seconds) {
                        report.put("cacheWriteAndHashMs", seconds * 1000);
                        phaseUnchecked("development-setup-graph-released", output, report, memory);
                    }
                    @Override public void constraintCacheWriteFailed(Exception failure) {
                        throw new IllegalStateException("This experiment requires a cache", failure);
                    }
                });
        report.put("setupIncludingCacheMs", elapsed(start));
        report.put("cacheBytes", Files.size(keys.resolve(Groth16Pipeline.R1CS_CACHE)));
        report.put("keyStoreBytes", directoryBytes(keys) - Files.size(keys.resolve(Groth16Pipeline.R1CS_CACHE)));
        checkpoint(output, report, memory);
    }

    private static Groth16Pipeline.Compiled compile(String algorithm, int length, int publicCount) {
        var graph = circuit(algorithm, length, publicCount);
        var system = graph.compileR1CS(CURVE);
        return new Groth16Pipeline.Compiled(system.flat(), system.numConstraints(), system.numWires(), system.numPublicInputs());
    }

    private static BigInteger[] witness(String algorithm, int length, Map<String, List<BigInteger>> input, BigInteger[] publicInputs) {
        var graph = circuit(algorithm, length, publicInputs.length);
        BigInteger[] result = graph.calculateWitness(input, CURVE);
        require(Arrays.equals(publicInputs, Arrays.copyOfRange(result, 1, publicInputs.length + 1)), "Digest mismatch");
        return result; // graph is out of scope before the caller allocates packed scalars
    }

    private static void dimensions(Groth16Pipeline.Compiled compiled, Map<String, Object> report) {
        report.put("constraints", compiled.numConstraints()); report.put("wires", compiled.numWires());
        report.put("publicInputs", compiled.numPublic()); report.put("fingerprint", compiled.fingerprint());
        report.put("r1csCanonicalSha256", compiled.r1csSha256());
        var flat = compiled.flat();
        report.put("terms", Map.of("a", flat.a().nnz(), "b", flat.b().nnz(), "c", flat.c().nnz(),
                "total", (long) flat.a().nnz() + flat.b().nnz() + flat.c().nnz()));
        report.put("csrPayloadBytes", 12L * (flat.rows() + 1) + 8L * (flat.a().nnz() + (long) flat.b().nnz() + flat.c().nnz()));
        report.put("dictionaryEntries", flat.dictionary().length);
        if (((Number) report.get("messageBytes")).intValue() == 16384) {
            String expected = DOCUMENT_FINGERPRINTS.get((String) report.get("algorithm"));
            require(compiled.fingerprint().equals(expected), "Original document relation fingerprint changed");
            report.put("originalDocumentRelationMatches", true);
        }
    }

    private static void phaseUnchecked(String name, Path output, Map<String, Object> report, HeapSampler memory) {
        try { phase(name, output, report, memory); }
        catch (IOException failure) { throw new UncheckedIOException(failure); }
    }
    private static void phase(String name, Path output, Map<String, Object> report, HeapSampler memory) throws IOException {
        stage = name; report.put("currentStage", name); report.put("phaseState", "running");
        checkpoint(output, report, memory);
    }
    private static void checkpoint(Path output, Map<String, Object> report, HeapSampler memory) throws IOException {
        report.put("sampledHeapPeakBytes", memory.peak());
        report.put("checkpointHeapUsedBytes", ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed());
        report.put("checkpointTimestamp", Instant.now().toString());
        Path pending = output.resolve("progress.pending.json"); write(pending, report);
        Files.move(pending, output.resolve("progress.json"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }
    private static void write(Path path, Map<String, Object> report) throws IOException {
        JSON.writerWithDefaultPrettyPrinter().writeValue(path.toFile(), report);
    }
}
