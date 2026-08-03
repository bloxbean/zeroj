package com.bloxbean.cardano.zeroj.jmt.load;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.AuthenticatedStateCircuitManifest;
import com.bloxbean.cardano.zeroj.api.Groth16ArtifactBundleIdentity;
import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.R1CSFlat;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.Bls12381Codecs;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp;
import com.bloxbean.cardano.zeroj.bls12381.field.Fp2;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Keys;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16Pipeline;
import com.bloxbean.cardano.zeroj.crypto.groth16.Groth16ProofBLS381;
import com.bloxbean.cardano.zeroj.crypto.groth16.ProverBackend;
import com.bloxbean.cardano.zeroj.crypto.msm.FlatScalars;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.circuit.PoseidonJmtCircuitTemplates;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtProfile;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16VerificationKeyCodec;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Complete setup/prove/verify benchmark for the bounded JMT inclusion template. */
public final class PoseidonJmtCircuitBenchmark {
    private static final BigInteger BENCHMARK_TAU = new BigInteger(
            "4a4d542d62656e63686d61726b2d746f7869632d77617374652d7631", 16)
            .mod(MontFr381.modulus());

    private final JmtLoadOptions options;
    private final JmtRunFiles files;

    public PoseidonJmtCircuitBenchmark(JmtLoadOptions options) {
        this.options = options;
        files = new JmtRunFiles(options.workDir());
    }

    public CircuitResult run(PoseidonJmtProofRunner.ProofRun proofRun) throws IOException {
        PoseidonJmtProofRunner.ProofArtifact artifact = proofRun.artifacts().stream()
                .max(Comparator.comparingInt(PoseidonJmtProofRunner.ProofArtifact::levels))
                .orElseThrow();
        if (artifact.levels() > options.maxLevels()) {
            throw new IllegalStateException("Selected JMT proof depth " + artifact.levels()
                    + " exceeds MAX_LEVELS=" + options.maxLevels());
        }

        String startedAt = Instant.now().toString();
        try (HeapSampler heap = new HeapSampler()) {
            BigInteger rootInput = PoseidonJmtHash.decode(proofRun.root());
            ZkInputMap inputMap = new ZkInputMap().put("root", rootInput);
            artifact.witness().putInto(inputMap);
            Map<String, List<BigInteger>> witnessInputs = inputMap.toWitnessMap();
            BigInteger[] publicInputs = {rootInput};

            CompiledCircuit compiled = compileCircuit();
            var pipelineCircuit = new Groth16Pipeline.Compiled(
                    compiled.flat(), compiled.constraintsCount(), compiled.wires(),
                    compiled.publicInputs());
            String fingerprint = pipelineCircuit.fingerprint();
            String r1csSha256 = pipelineCircuit.r1csSha256();
            String templateId = "zeroj-jmt-v1-inclusion-s" + options.maxLevels() + "-p1";
            System.out.printf(
                    "JMT circuit %s: %,d constraints, %,d wires, %d public; "
                            + "build %.3f s, compile %.3f s%n",
                    fingerprint, compiled.constraintsCount(), compiled.wires(),
                    compiled.publicInputs(), compiled.buildSeconds(), compiled.compileSeconds());

            double witnessBuildSeconds;
            double witnessSeconds;
            double graphReleaseGcSeconds = 0;
            double setupSeconds = 0;
            double keyLoadSeconds = 0;
            double proveSeconds = 0;
            double positiveVerifySeconds = 0;
            double negativeVerifySeconds = 0;
            List<Double> proveTrialSeconds = List.of();
            List<Double> positiveVerifyTrialSeconds = List.of();
            List<Double> negativeVerifyTrialSeconds = List.of();
            Boolean positiveVerified = null;
            Boolean negativeRejected = null;
            int compressedProofBytes = 0;
            long keyStoreBytes = 0;
            long verificationKeyBytes = 0;
            String artifactDirectory = null;
            String setupProvenance = "none";

            if (options.setupMode() == JmtLoadOptions.SetupMode.IN_MEMORY) {
                requireBenchmarkSetupOptIn();
                long setupStarted = System.nanoTime();
                Groth16Keys keys = Groth16Keys.setupInMemory(
                        compiled.constraints(), compiled.wires(), compiled.publicInputs(), BENCHMARK_TAU);
                setupSeconds = elapsed(setupStarted);
                setupProvenance = "single-party-fixed-toxic-waste-benchmark-only/in-memory";
                BoxedWitness witness = boxedWitness(witnessInputs, compiled.wires());
                witnessBuildSeconds = witness.buildSeconds();
                witnessSeconds = witness.witnessSeconds();
                requirePublicRoot(rootInput, witness.values()[1]);
                List<R1CSConstraint> inMemoryConstraints = compiled.constraints();
                try (keys) {
                    TrialRun trials = runTrials(
                            keys, publicInputs,
                            () -> keys.prove(witness.values(), inMemoryConstraints));
                    Groth16ProofBLS381 proof = trials.lastProof();
                    proveSeconds = trials.medianProveSeconds();
                    positiveVerifySeconds = trials.medianPositiveVerifySeconds();
                    negativeVerifySeconds = trials.medianNegativeVerifySeconds();
                    proveTrialSeconds = trials.proveSeconds();
                    positiveVerifyTrialSeconds = trials.positiveVerifySeconds();
                    negativeVerifyTrialSeconds = trials.negativeVerifySeconds();
                    positiveVerified = true;
                    negativeRejected = true;
                    compressedProofBytes = trials.proofBytes();
                    ArtifactStats cardano = writeCardanoArtifacts(
                            keys, proof, rootInput, templateId, fingerprint, r1csSha256,
                            setupProvenance, compiled.constraintsCount(), compiled.wires(),
                            compiled.publicInputs());
                    verificationKeyBytes = cardano.verificationKeyBytes();
                    artifactDirectory = cardano.directory();
                }
            } else {
                Path cache = options.keysDir().resolve(Groth16Pipeline.R1CS_CACHE);
                if (options.setupMode() == JmtLoadOptions.SetupMode.STORE) {
                    requireBenchmarkSetupOptIn();
                    requireEmptyOrMissing(options.keysDir());
                    long setupStarted = System.nanoTime();
                    Groth16Pipeline.setup(pipelineCircuit, BENCHMARK_TAU, options.keysDir(), true);
                    setupSeconds = elapsed(setupStarted);
                    setupProvenance = "single-party-fixed-toxic-waste-benchmark-only/sparse-store";
                } else if (options.setupMode() == JmtLoadOptions.SetupMode.LOAD) {
                    if (!Groth16Pipeline.cacheMatches(cache, fingerprint)) {
                        throw new IllegalStateException(
                                "Groth16 key bundle does not match " + fingerprint);
                    }
                    setupProvenance = "loaded-existing-key-bundle";
                }
                pipelineCircuit = null;
                compiled = compiled.withoutHeapGraph();
                graphReleaseGcSeconds = requestCollection();
                FlatWitness witness = flatWitness(witnessInputs, compiled.wires());
                witnessBuildSeconds = witness.buildSeconds();
                witnessSeconds = witness.witnessSeconds();
                requirePublicRoot(rootInput, witness.values().toBigInteger(1));

                if (options.setupMode() != JmtLoadOptions.SetupMode.NONE) {
                    long loadStarted = System.nanoTime();
                    Groth16Keys keys = Groth16Keys.load(options.keysDir());
                    keyLoadSeconds = elapsed(loadStarted);
                    try (keys) {
                        TrialRun trials = runTrials(keys, publicInputs, () ->
                                Groth16Pipeline.prove(
                                        keys, cache, fingerprint,
                                        () -> { throw new IllegalStateException(
                                                "Matching R1CS cache disappeared"); },
                                        witness::values, 0, ProverBackend.PURE_JAVA));
                        Groth16ProofBLS381 proof = trials.lastProof();
                        proveSeconds = trials.medianProveSeconds();
                        positiveVerifySeconds = trials.medianPositiveVerifySeconds();
                        negativeVerifySeconds = trials.medianNegativeVerifySeconds();
                        proveTrialSeconds = trials.proveSeconds();
                        positiveVerifyTrialSeconds = trials.positiveVerifySeconds();
                        negativeVerifyTrialSeconds = trials.negativeVerifySeconds();
                        positiveVerified = true;
                        negativeRejected = true;
                        compressedProofBytes = trials.proofBytes();
                        ArtifactStats cardano = writeCardanoArtifacts(
                                keys, proof, rootInput, templateId, fingerprint, r1csSha256,
                                setupProvenance, compiled.constraintsCount(), compiled.wires(),
                                compiled.publicInputs());
                        verificationKeyBytes = cardano.verificationKeyBytes();
                        artifactDirectory = cardano.directory();
                    }
                    keyStoreBytes = JmtRunFiles.directoryBytes(options.keysDir());
                }
            }

            CircuitResult result = new CircuitResult(
                    startedAt, Instant.now().toString(), artifact.index(), artifact.levels(),
                    options.maxLevels(),
                    templateId,
                    compiled.constraintsCount(), compiled.wires(), compiled.publicInputs(),
                    compiled.privateInputs(), fingerprint, r1csSha256,
                    compiled.buildSeconds(), compiled.compileSeconds(), witnessBuildSeconds,
                    witnessSeconds, graphReleaseGcSeconds,
                    options.setupMode().name().toLowerCase().replace('_', '-'), setupProvenance,
                    setupSeconds, keyLoadSeconds, proveSeconds, positiveVerifySeconds,
                    negativeVerifySeconds, positiveVerified, negativeRejected,
                    options.circuitTrials(), proveTrialSeconds,
                    positiveVerifyTrialSeconds, negativeVerifyTrialSeconds,
                    compressedProofBytes, verificationKeyBytes, artifactDirectory,
                    options.keysDir().toString(), keyStoreBytes, heap.peakBytes(),
                    heap.peakRssBytes(), heap.peakRssMinusUsedHeapBytes(),
                    heap.rssSamples(), heap.rssSource());
            files.writeReportSection("circuit-s" + options.maxLevels(), result, options);
            return result;
        }
    }

    private CompiledCircuit compileCircuit() {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonJmtCircuitTemplates.inclusion(options.maxLevels());
        double buildSeconds = elapsed(buildStarted);
        long compileStarted = System.nanoTime();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        return new CompiledCircuit(
                r1cs.flat(), r1cs.constraints(), r1cs.numConstraints(), r1cs.numWires(),
                r1cs.numPublicInputs(), r1cs.numPrivateInputs(), buildSeconds,
                elapsed(compileStarted));
    }

    private TrialRun runTrials(
            Groth16Keys keys, BigInteger[] publicInputs, ProofFactory factory) throws IOException {
        List<Double> prove = new java.util.ArrayList<>(options.circuitTrials());
        List<Double> positive = new java.util.ArrayList<>(options.circuitTrials());
        List<Double> negative = new java.util.ArrayList<>(options.circuitTrials());
        Groth16ProofBLS381 last = null;
        int proofBytes = 0;
        for (int trial = 0; trial < options.circuitTrials(); trial++) {
            long proveStarted = System.nanoTime();
            last = factory.create();
            prove.add(elapsed(proveStarted));
            Verification verification = verify(keys, last, publicInputs);
            positive.add(verification.positiveSeconds());
            negative.add(verification.negativeSeconds());
            proofBytes = verification.proofBytes();
        }
        return new TrialRun(last, List.copyOf(prove), List.copyOf(positive),
                List.copyOf(negative), median(prove), median(positive), median(negative), proofBytes);
    }

    private static double median(List<Double> values) {
        double[] sorted = values.stream().mapToDouble(Double::doubleValue).sorted().toArray();
        int middle = sorted.length / 2;
        return (sorted.length & 1) == 1
                ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2.0;
    }

    private BoxedWitness boxedWitness(Map<String, List<BigInteger>> inputs, int wires) {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonJmtCircuitTemplates.inclusion(options.maxLevels());
        double buildSeconds = elapsed(buildStarted);
        long witnessStarted = System.nanoTime();
        BigInteger[] values = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        if (values.length != wires) throw new IllegalStateException("JMT witness wire count drift");
        return new BoxedWitness(values, buildSeconds, elapsed(witnessStarted));
    }

    private FlatWitness flatWitness(Map<String, List<BigInteger>> inputs, int wires) {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonJmtCircuitTemplates.inclusion(options.maxLevels());
        double buildSeconds = elapsed(buildStarted);
        long witnessStarted = System.nanoTime();
        long[] limbs = circuit.calculateWitnessFlat(inputs, CurveId.BLS12_381);
        if (limbs.length != wires * 4L) throw new IllegalStateException("JMT flat witness wire count drift");
        return new FlatWitness(FlatScalars.wrap(limbs, wires), buildSeconds, elapsed(witnessStarted));
    }

    private static Verification verify(
            Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger[] publicInputs) {
        long positiveStarted = System.nanoTime();
        boolean positive = pairingVerify(keys, proof, publicInputs);
        double positiveSeconds = elapsed(positiveStarted);
        BigInteger[] mutated = publicInputs.clone();
        mutated[0] = mutated[0].add(BigInteger.ONE).mod(MontFr381.modulus());
        long negativeStarted = System.nanoTime();
        boolean negative = !pairingVerify(keys, proof, mutated);
        double negativeSeconds = elapsed(negativeStarted);
        if (!positive || !negative) {
            throw new IllegalStateException("JMT Groth16 positive/negative verification gate failed");
        }
        int proofBytes = Bls12381Codecs.g1ToCompressed(toG1(proof.a())).length
                + Bls12381Codecs.g2ToCompressed(toG2(proof.b())).length
                + Bls12381Codecs.g1ToCompressed(toG1(proof.c())).length;
        return new Verification(positive, negative, positiveSeconds, negativeSeconds, proofBytes);
    }

    private ArtifactStats writeCardanoArtifacts(
            Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger root,
            String templateId, String fingerprint, String r1csSha256,
            String setupProvenance, int constraints, int wires, int publicInputs) throws IOException {
        var vk = ProverToCardano.compressVk(keys);
        var compressedProof = ProverToCardano.compressProof(proof);
        byte[] verificationKey = Groth16VerificationKeyCodec.encode(vk);
        String verificationKeySha256 = sha256(verificationKey);
        byte[] publicRootBytes = PoseidonJmtHash.encode(root);
        String dimensionFingerprint = "c" + constraints + "-w" + wires + "-p" + publicInputs;
        String expectedFingerprint = dimensionFingerprint + "-r" + r1csSha256;
        if (!expectedFingerprint.equals(fingerprint)) {
            throw new IllegalStateException("exact circuit fingerprint does not bind the canonical R1CS");
        }
        var circuitManifest = new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                templateId,
                PoseidonJmtProfile.PROFILE_ID,
                AuthenticatedStateCircuitManifest.Operation.INCLUSION,
                options.maxLevels(),
                List.of(new AuthenticatedStateCircuitManifest.PublicInput(
                        0, "root", "field", "canonical-unsigned-big-endian-32")),
                AuthenticatedStateCircuitManifest.POSEIDON_PARAMETER_FINGERPRINT,
                AuthenticatedStateCircuitManifest.R1CS_FORMAT,
                r1csSha256,
                dimensionFingerprint,
                "groth16",
                "bls12-381",
                AuthenticatedStateCircuitManifest.VK_FORMAT,
                verificationKeySha256,
                null,
                null,
                new AuthenticatedStateCircuitManifest.SetupProvenance(
                        "benchmark-single-party",
                        setupProvenance + "/" + fingerprint,
                        null,
                        false));
        byte[] circuitManifestBytes = circuitManifest.canonicalJsonBytes();
        String bundleSha256 = Groth16ArtifactBundleIdentity.sha256(
                circuitManifest,
                verificationKey,
                compressedProof.piA(),
                compressedProof.piB(),
                compressedProof.piC(),
                List.of(publicRootBytes));
        Path directory = files.cardanoArtifactsDir(
                templateId, fingerprint, verificationKeySha256, bundleSha256);
        Map<String, ArtifactFile> artifactFiles = new LinkedHashMap<>();
        writeArtifact(directory, artifactFiles, "proof-a.g1", compressedProof.piA());
        writeArtifact(directory, artifactFiles, "proof-b.g2", compressedProof.piB());
        writeArtifact(directory, artifactFiles, "proof-c.g1", compressedProof.piC());
        writeArtifact(directory, artifactFiles, "vk-alpha.g1", vk.alpha());
        writeArtifact(directory, artifactFiles, "vk-beta.g2", vk.beta());
        writeArtifact(directory, artifactFiles, "vk-gamma.g2", vk.gamma());
        writeArtifact(directory, artifactFiles, "vk-delta.g2", vk.delta());
        for (int index = 0; index < vk.ic().size(); index++) {
            writeArtifact(directory, artifactFiles,
                    "vk-ic-" + index + ".g1", vk.ic().get(index));
        }
        writeArtifact(directory, artifactFiles, "verification-key.bin", verificationKey);
        writeArtifact(directory, artifactFiles, "public-input-root.bin", publicRootBytes);
        writeArtifact(directory, artifactFiles, "circuit-manifest.json", circuitManifestBytes);
        String circuitManifestSha256 = sha256(circuitManifestBytes);
        @SuppressWarnings("unchecked")
        Map<String, Object> canonicalSetupProvenance = (Map<String, Object>)
                circuitManifest.toJsonModel().get("setupProvenance");
        files.writeCardanoArtifactManifest(directory, new ArtifactManifest(
                "zeroj-cardano-groth16-artifacts-v2",
                Groth16ArtifactBundleIdentity.SCHEMA,
                PoseidonJmtProfile.PROFILE_ID,
                "inclusion", templateId, fingerprint, r1csSha256,
                circuitManifestSha256, verificationKeySha256, bundleSha256,
                List.of("root"), List.of("public-input-root.bin"),
                canonicalSetupProvenance, false, Instant.now().toString(),
                Map.copyOf(artifactFiles)));
        long bytes = vk.alpha().length + vk.beta().length + vk.gamma().length + vk.delta().length
                + vk.ic().stream().mapToLong(value -> value.length).sum();
        return new ArtifactStats(directory.toString(), bytes);
    }

    private void writeArtifact(
            Path directory, Map<String, ArtifactFile> artifactFiles,
            String name, byte[] value) throws IOException {
        files.writeCardanoArtifact(directory, name, value);
        artifactFiles.put(name, new ArtifactFile(value.length, sha256(value)));
    }

    private static String sha256(byte[] value) {
        try {
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private void requireBenchmarkSetupOptIn() {
        if (!options.allowInsecureSetup()) {
            throw new IllegalStateException("Local Groth16 setup is insecure; explicitly set "
                    + "--allow-insecure-setup=true for benchmarks only");
        }
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    private static void requireEmptyOrMissing(Path directory) throws IOException {
        if (Files.notExists(directory)) return;
        try (var entries = Files.list(directory)) {
            if (entries.findAny().isPresent()) {
                throw new IllegalStateException("Refusing to overwrite non-empty key directory: " + directory);
            }
        }
    }

    private static void requirePublicRoot(BigInteger expected, BigInteger actual) {
        if (!expected.equals(actual)) throw new IllegalStateException("JMT witness public root drift");
    }

    private static double requestCollection() {
        long started = System.nanoTime();
        System.gc();
        return elapsed(started);
    }

    private static boolean pairingVerify(
            Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger[] publicInputs) {
        if (keys.ic().length != publicInputs.length + 1) {
            throw new IllegalStateException("Verification key IC count does not match public inputs");
        }
        G1Point vkX = toG1(keys.ic()[0]);
        for (int index = 0; index < publicInputs.length; index++) {
            vkX = vkX.add(toG1(keys.ic()[index + 1]).scalarMul(publicInputs[index]));
        }
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{toG1(proof.a()), toG1(keys.pk().alphaG1()).negate(),
                        vkX.negate(), toG1(proof.c()).negate()},
                new G2Point[]{toG2(proof.b()), toG2(keys.pk().betaG2()),
                        toG2(keys.gammaG2()), toG2(keys.pk().deltaG2())});
    }

    private static G1Point toG1(JacobianG1BLS381.AffineG1 point) {
        return point.isInfinity() ? G1Point.INFINITY
                : new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 point) {
        return point.isInfinity() ? G2Point.INFINITY
                : new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    private static double elapsed(long started) {
        return (System.nanoTime() - started) / 1_000_000_000.0;
    }

    private record CompiledCircuit(
            R1CSFlat flat, List<R1CSConstraint> constraints, int constraintsCount, int wires,
            int publicInputs, int privateInputs, double buildSeconds, double compileSeconds) {
        private CompiledCircuit withoutHeapGraph() {
            return new CompiledCircuit(null, null, constraintsCount, wires, publicInputs,
                    privateInputs, buildSeconds, compileSeconds);
        }
    }
    private record BoxedWitness(BigInteger[] values, double buildSeconds, double witnessSeconds) {}
    private record FlatWitness(FlatScalars values, double buildSeconds, double witnessSeconds) {}
    private record Verification(boolean positive, boolean negativeRejected,
                                double positiveSeconds, double negativeSeconds, int proofBytes) {}
    @FunctionalInterface
    private interface ProofFactory {
        Groth16ProofBLS381 create() throws IOException;
    }
    private record TrialRun(
            Groth16ProofBLS381 lastProof,
            List<Double> proveSeconds,
            List<Double> positiveVerifySeconds,
            List<Double> negativeVerifySeconds,
            double medianProveSeconds,
            double medianPositiveVerifySeconds,
            double medianNegativeVerifySeconds,
            int proofBytes) {}
    private record ArtifactStats(String directory, long verificationKeyBytes) {}
    private record ArtifactFile(long bytes, String sha256) {}
    private record ArtifactManifest(
            String schema, String bundleIdentity, String profileId, String operation, String templateId,
            String exactCircuitFingerprint, String r1csSha256,
            String circuitManifestSha256, String verificationKeySha256, String bundleSha256,
            List<String> publicInputs, List<String> publicInputFiles,
            Map<String, Object> setupProvenance, boolean productionApproved, String generatedAt,
            Map<String, ArtifactFile> files) {}

    public record CircuitResult(
            String startedAt, String completedAt, long datasetIndex, int observedProofLevels,
            int maxLevels, String templateId, int constraints, int wires, int publicInputs,
            int privateInputs, String fingerprint, String r1csSha256,
            double compileCircuitBuildSeconds, double compileSeconds,
            double witnessCircuitBuildSeconds, double witnessSeconds,
            double graphReleaseGcSeconds, String setupMode, String setupProvenance,
            double setupSeconds, double keyLoadSeconds, double proveSeconds,
            double positiveVerifySeconds, double negativeVerifySeconds,
            Boolean positiveVerified, Boolean negativeInputRejected,
            int circuitTrials, List<Double> proveTrialSeconds,
            List<Double> positiveVerifyTrialSeconds,
            List<Double> negativeVerifyTrialSeconds,
            int compressedProofBytes, long cardanoVerificationKeyBytes,
            String cardanoArtifactsDirectory, String keysDirectory,
            long keyStoreBytes, long peakObservedHeapBytes,
            long peakObservedRssBytes, long peakRssMinusUsedHeapBytes,
            long rssSamples, String rssSource) {}
}
