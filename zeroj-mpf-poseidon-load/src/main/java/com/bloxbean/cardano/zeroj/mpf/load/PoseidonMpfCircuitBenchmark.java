package com.bloxbean.cardano.zeroj.mpf.load;

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
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.merkle.mpf.poseidon.profile.PoseidonMpfValueCommitment;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.Groth16VerificationKeyCodec;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class PoseidonMpfCircuitBenchmark {
    private static final BigInteger BENCHMARK_TAU = new BigInteger(
            "4d50462d62656e63686d61726b2d746f7869632d77617374652d7632", 16)
            .mod(MontFr381.modulus());

    private final LoadOptions options;
    private final RunFiles files;

    public PoseidonMpfCircuitBenchmark(LoadOptions options) {
        this.options = options;
        this.files = new RunFiles(options.workDir());
    }

    public CircuitResult run(PoseidonMpfProofRunner.ProofRun proofRun) throws IOException {
        var artifact = proofRun.circuitArtifact();
        if (artifact.steps() > options.maxSteps()) {
            throw new IllegalStateException("Selected proof has " + artifact.steps()
                    + " steps, exceeding MAX_STEPS=" + options.maxSteps());
        }

        String startedAt = Instant.now().toString();
        try (HeapSampler heap = new HeapSampler()) {
            var inputs = new ZkInputMap()
                    .put("root", PoseidonMpfHash.fieldFromDigestBytes(proofRun.root()))
                    .put("value_commitment", PoseidonMpfValueCommitment.field(artifact.value()));
            artifact.witness().putInto(inputs);
            Map<String, List<BigInteger>> witnessInputs = inputs.toWitnessMap();
            BigInteger rootInput = PoseidonMpfHash.fieldFromDigestBytes(proofRun.root());
            BigInteger[] publicInputs = {rootInput};

            CompiledCircuit compiled = compileCircuit();
            int constraints = compiled.constraintsCount();
            int wires = compiled.wires();
            int publicInputCount = compiled.publicInputs();
            int privateInputCount = compiled.privateInputs();
            double compileCircuitBuildSeconds = compiled.buildSeconds();
            double compileSeconds = compiled.compileSeconds();
            var pipelineCircuit = new Groth16Pipeline.Compiled(
                    compiled.flat(), constraints, wires, publicInputCount);
            String fingerprint = pipelineCircuit.fingerprint();
            String r1csSha256 = pipelineCircuit.r1csSha256();
            String templateId = "zeroj-mpf-v1-inclusion-s" + options.maxSteps() + "-p1";
            System.out.printf("circuit %s: %,d constraints, %,d wires, %d public; build %.3f s, compile %.3f s%n",
                    fingerprint, constraints, wires, publicInputCount,
                    compiled.buildSeconds(), compiled.compileSeconds());

            double witnessCircuitBuildSeconds;
            double witnessSeconds;
            double releaseGcSeconds = 0.0;
            double setupSeconds = 0.0;
            double keyLoadSeconds = 0.0;
            double proveSeconds = 0.0;
            double positiveVerifySeconds = 0.0;
            double negativeVerifySeconds = 0.0;
            List<Double> proveTrialSeconds = List.of();
            List<Double> positiveVerifyTrialSeconds = List.of();
            List<Double> negativeVerifyTrialSeconds = List.of();
            Boolean positiveVerified = null;
            Boolean negativeRejected = null;
            int compressedProofBytes = 0;
            long keyStoreBytes = 0L;
            long cardanoVerificationKeyBytes = 0L;
            String cardanoArtifactsDirectory = null;
            String setupProvenance = "none";

            if (options.setupMode() == LoadOptions.SetupMode.IN_MEMORY) {
                requireBenchmarkSetupOptIn();
                long setupStarted = System.nanoTime();
                Groth16Keys keys = Groth16Keys.setupInMemory(
                        compiled.constraints(), wires, publicInputCount, BENCHMARK_TAU);
                setupSeconds = secondsSince(setupStarted);
                setupProvenance = "single-party-fixed-toxic-waste-benchmark-only/in-memory";

                BoxedWitness witness = calculateBoxedWitness(witnessInputs, wires);
                witnessCircuitBuildSeconds = witness.buildSeconds();
                witnessSeconds = witness.witnessSeconds();
                if (!rootInput.equals(witness.values()[1])) {
                    throw new IllegalStateException("Witness public root does not match requested root");
                }
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
                    ArtifactStats artifacts = writeCardanoArtifacts(
                            keys, proof, rootInput, templateId, fingerprint, r1csSha256,
                            setupProvenance, constraints, wires, publicInputCount);
                    cardanoVerificationKeyBytes = artifacts.verificationKeyBytes();
                    cardanoArtifactsDirectory = artifacts.directory();
                }
            } else {
                Path constraintCache = options.keysDir().resolve(Groth16Pipeline.R1CS_CACHE);
                if (options.setupMode() == LoadOptions.SetupMode.STORE) {
                    requireBenchmarkSetupOptIn();
                    requireEmptyOrMissing(options.keysDir());
                    long setupStarted = System.nanoTime();
                    Groth16Pipeline.setup(pipelineCircuit, BENCHMARK_TAU, options.keysDir(), true);
                    setupSeconds = secondsSince(setupStarted);
                    setupProvenance = "single-party-fixed-toxic-waste-benchmark-only/sparse-store";
                } else if (options.setupMode() == LoadOptions.SetupMode.LOAD) {
                    if (!Groth16Pipeline.cacheMatches(constraintCache, fingerprint)) {
                        throw new IllegalStateException("Groth16 key bundle does not match " + fingerprint
                                + ": " + options.keysDir());
                    }
                    setupProvenance = "loaded-existing-key-bundle";
                }

                // The compile graph and heap-backed R1CS must not coexist with
                // witness generation or the prover's FFT/MSM phase.
                pipelineCircuit = null;
                compiled = null;
                releaseGcSeconds = requestCollection();
                FlatWitness witness = calculateFlatWitness(witnessInputs, wires);
                witnessCircuitBuildSeconds = witness.buildSeconds();
                witnessSeconds = witness.witnessSeconds();
                if (!rootInput.equals(witness.values().toBigInteger(1))) {
                    throw new IllegalStateException("Witness public root does not match requested root");
                }

                if (options.setupMode() != LoadOptions.SetupMode.NONE) {
                    long loadStarted = System.nanoTime();
                    Groth16Keys keys = Groth16Keys.load(options.keysDir());
                    keyLoadSeconds = secondsSince(loadStarted);
                    try (keys) {
                        TrialRun trials = runTrials(keys, publicInputs, () ->
                                Groth16Pipeline.prove(
                                        keys,
                                        constraintCache,
                                        fingerprint,
                                        () -> { throw new IllegalStateException(
                                                "Matching R1CS cache disappeared"); },
                                        witness::values,
                                        0,
                                        ProverBackend.PURE_JAVA));
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
                        ArtifactStats artifacts = writeCardanoArtifacts(
                                keys, proof, rootInput, templateId, fingerprint, r1csSha256,
                                setupProvenance, constraints, wires, publicInputCount);
                        cardanoVerificationKeyBytes = artifacts.verificationKeyBytes();
                        cardanoArtifactsDirectory = artifacts.directory();
                    }
                    keyStoreBytes = RunFiles.directoryBytes(options.keysDir());
                }
            }

            if (positiveVerified != null) {
                System.out.printf("Groth16 prove %.3f s, verify %.3f s, negative %.3f s, compressed proof %d bytes%n",
                        proveSeconds, positiveVerifySeconds, negativeVerifySeconds, compressedProofBytes);
            }

            CircuitResult result = new CircuitResult(
                    startedAt,
                    Instant.now().toString(),
                    artifact.index(),
                    artifact.steps(),
                    options.maxSteps(),
                    templateId,
                    "inclusion/branch-path",
                    constraints,
                    wires,
                    publicInputCount,
                    privateInputCount,
                    fingerprint,
                    r1csSha256,
                    options.keysDir().toString(),
                    compileCircuitBuildSeconds,
                    witnessCircuitBuildSeconds,
                    witnessSeconds,
                    compileSeconds,
                    releaseGcSeconds,
                    options.setupMode().name().toLowerCase().replace('_', '-'),
                    setupProvenance,
                    setupSeconds,
                    keyLoadSeconds,
                    proveSeconds,
                    positiveVerifySeconds,
                    negativeVerifySeconds,
                    positiveVerified,
                    negativeRejected,
                    options.circuitTrials(),
                    proveTrialSeconds,
                    positiveVerifyTrialSeconds,
                    negativeVerifyTrialSeconds,
                    compressedProofBytes,
                    cardanoVerificationKeyBytes,
                    cardanoArtifactsDirectory,
                    keyStoreBytes,
                    heap.peakBytes(),
                    heap.peakRssBytes(),
                    heap.peakRssMinusUsedHeapBytes(),
                    heap.rssSamples(),
                    heap.rssSource());
            files.writeReportSection("circuit-s" + options.maxSteps(), result, options);
            return result;
        }
    }

    private CompiledCircuit compileCircuit() {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonMpfInclusionCircuit.build(options.maxSteps());
        double buildSeconds = secondsSince(buildStarted);
        long compileStarted = System.nanoTime();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        double compileSeconds = secondsSince(compileStarted);
        return new CompiledCircuit(
                r1cs.flat(), r1cs.constraints(), r1cs.numConstraints(), r1cs.numWires(),
                r1cs.numPublicInputs(), r1cs.numPrivateInputs(), buildSeconds, compileSeconds);
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
            prove.add(secondsSince(proveStarted));
            ProofVerification verification = verifyProof(keys, last, publicInputs);
            positive.add(verification.positiveSeconds());
            negative.add(verification.negativeSeconds());
            proofBytes = verification.compressedBytes();
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

    private BoxedWitness calculateBoxedWitness(Map<String, List<BigInteger>> inputs, int expectedWires) {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonMpfInclusionCircuit.build(options.maxSteps());
        double buildSeconds = secondsSince(buildStarted);
        long witnessStarted = System.nanoTime();
        BigInteger[] values = circuit.calculateWitness(inputs, CurveId.BLS12_381);
        double witnessSeconds = secondsSince(witnessStarted);
        if (values.length != expectedWires) {
            throw new IllegalStateException("Witness has " + values.length + " wires, expected " + expectedWires);
        }
        return new BoxedWitness(values, buildSeconds, witnessSeconds);
    }

    private FlatWitness calculateFlatWitness(Map<String, List<BigInteger>> inputs, int expectedWires) {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonMpfInclusionCircuit.build(options.maxSteps());
        double buildSeconds = secondsSince(buildStarted);
        long witnessStarted = System.nanoTime();
        long[] limbs = circuit.calculateWitnessFlat(inputs, CurveId.BLS12_381);
        double witnessSeconds = secondsSince(witnessStarted);
        if (limbs.length != expectedWires * 4L) {
            throw new IllegalStateException("Flat witness has " + limbs.length + " limbs, expected "
                    + (expectedWires * 4L));
        }
        return new FlatWitness(FlatScalars.wrap(limbs, expectedWires), buildSeconds, witnessSeconds);
    }

    private static ProofVerification verifyProof(
            Groth16Keys keys,
            Groth16ProofBLS381 proof,
            BigInteger[] publicInputs) {
        long verifyStarted = System.nanoTime();
        boolean positive = pairingVerify(keys, proof, publicInputs);
        double positiveSeconds = secondsSince(verifyStarted);

        BigInteger[] mutated = publicInputs.clone();
        mutated[0] = mutated[0].add(BigInteger.ONE).mod(MontFr381.modulus());
        long negativeStarted = System.nanoTime();
        boolean negativeRejected = !pairingVerify(keys, proof, mutated);
        double negativeSeconds = secondsSince(negativeStarted);
        if (!positive || !negativeRejected) {
            throw new IllegalStateException("Groth16 verification gate failed: positive="
                    + positive + ", negativeRejected=" + negativeRejected);
        }
        int compressedBytes = Bls12381Codecs.g1ToCompressed(toG1(proof.a())).length
                + Bls12381Codecs.g2ToCompressed(toG2(proof.b())).length
                + Bls12381Codecs.g1ToCompressed(toG1(proof.c())).length;
        return new ProofVerification(positive, negativeRejected, positiveSeconds, negativeSeconds, compressedBytes);
    }

    private ArtifactStats writeCardanoArtifacts(
            Groth16Keys keys,
            Groth16ProofBLS381 proof,
            BigInteger publicRoot,
            String templateId,
            String fingerprint,
            String r1csSha256,
            String setupProvenance,
            int constraints,
            int wires,
            int publicInputs) throws IOException {
        var compressedVk = ProverToCardano.compressVk(keys);
        var compressedProof = ProverToCardano.compressProof(proof);
        byte[] verificationKey = Groth16VerificationKeyCodec.encode(compressedVk);
        String verificationKeySha256 = sha256(verificationKey);
        byte[] publicRootBytes = PoseidonMpfHash.toDigestBytes(publicRoot);
        String dimensionFingerprint = "c" + constraints + "-w" + wires + "-p" + publicInputs;
        String expectedFingerprint = dimensionFingerprint + "-r" + r1csSha256;
        if (!expectedFingerprint.equals(fingerprint)) {
            throw new IllegalStateException("exact circuit fingerprint does not bind the canonical R1CS");
        }
        var circuitManifest = new AuthenticatedStateCircuitManifest(
                AuthenticatedStateCircuitManifest.SCHEMA_VERSION,
                templateId,
                PoseidonMpfHash.PROFILE_ID,
                AuthenticatedStateCircuitManifest.Operation.INCLUSION,
                options.maxSteps(),
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
        writeArtifact(directory, artifactFiles, "vk-alpha.g1", compressedVk.alpha());
        writeArtifact(directory, artifactFiles, "vk-beta.g2", compressedVk.beta());
        writeArtifact(directory, artifactFiles, "vk-gamma.g2", compressedVk.gamma());
        writeArtifact(directory, artifactFiles, "vk-delta.g2", compressedVk.delta());
        for (int i = 0; i < compressedVk.ic().size(); i++) {
            writeArtifact(directory, artifactFiles,
                    "vk-ic-" + i + ".g1", compressedVk.ic().get(i));
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
                PoseidonMpfHash.PROFILE_ID,
                "inclusion", templateId, fingerprint, r1csSha256,
                circuitManifestSha256, verificationKeySha256, bundleSha256,
                List.of("root"), List.of("public-input-root.bin"),
                canonicalSetupProvenance, false, Instant.now().toString(),
                Map.copyOf(artifactFiles)));
        long verificationKeyBytes = compressedVk.alpha().length
                + compressedVk.beta().length
                + compressedVk.gamma().length
                + compressedVk.delta().length
                + compressedVk.ic().stream().mapToLong(value -> value.length).sum();
        return new ArtifactStats(directory.toString(), verificationKeyBytes);
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

    private static double requestCollection() {
        long started = System.nanoTime();
        System.gc();
        return secondsSince(started);
    }

    private void requireBenchmarkSetupOptIn() {
        if (!options.allowInsecureSetup()) {
            throw new IllegalStateException("Local Groth16 setup is insecure. Re-run with "
                    + "--allow-insecure-setup=true only for a benchmark, or use --setup=load");
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

    private static boolean pairingVerify(Groth16Keys keys, Groth16ProofBLS381 proof, BigInteger[] publicInputs) {
        if (keys.ic().length != publicInputs.length + 1) {
            throw new IllegalStateException("Verification key IC count does not match public inputs");
        }
        G1Point vkX = toG1(keys.ic()[0]);
        for (int i = 0; i < publicInputs.length; i++) {
            vkX = vkX.add(toG1(keys.ic()[i + 1]).scalarMul(publicInputs[i]));
        }
        return BLS12381Pairing.pairingCheck(
                new G1Point[]{
                        toG1(proof.a()),
                        toG1(keys.pk().alphaG1()).negate(),
                        vkX.negate(),
                        toG1(proof.c()).negate()},
                new G2Point[]{
                        toG2(proof.b()),
                        toG2(keys.pk().betaG2()),
                        toG2(keys.gammaG2()),
                        toG2(keys.pk().deltaG2())});
    }

    private static G1Point toG1(JacobianG1BLS381.AffineG1 point) {
        if (point.isInfinity()) return G1Point.INFINITY;
        return new G1Point(Fp.of(point.xBigInt()), Fp.of(point.yBigInt()));
    }

    private static G2Point toG2(JacobianG2BLS381.AffineG2 point) {
        if (point.isInfinity()) return G2Point.INFINITY;
        return new G2Point(
                Fp2.of(Fp.of(point.x().reBigInt()), Fp.of(point.x().imBigInt())),
                Fp2.of(Fp.of(point.y().reBigInt()), Fp.of(point.y().imBigInt())));
    }

    private static double secondsSince(long startedNanos) {
        return (System.nanoTime() - startedNanos) / 1_000_000_000.0;
    }

    private record CompiledCircuit(
            R1CSFlat flat,
            List<R1CSConstraint> constraints,
            int constraintsCount,
            int wires,
            int publicInputs,
            int privateInputs,
            double buildSeconds,
            double compileSeconds) {}

    private record BoxedWitness(BigInteger[] values, double buildSeconds, double witnessSeconds) {}

    private record FlatWitness(FlatScalars values, double buildSeconds, double witnessSeconds) {}

    private record ProofVerification(
            boolean positiveVerified,
            boolean negativeRejected,
            double positiveSeconds,
            double negativeSeconds,
            int compressedBytes) {}

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
            String startedAt,
            String completedAt,
            long datasetIndex,
            int observedProofSteps,
            int maxSteps,
            String templateId,
            String proofForm,
            int constraints,
            int wires,
            int publicInputs,
            int privateInputs,
            String fingerprint,
            String r1csSha256,
            String keysDirectory,
            double compileCircuitBuildSeconds,
            double witnessCircuitBuildSeconds,
            double witnessSeconds,
            double compileSeconds,
            double graphReleaseGcSeconds,
            String setupMode,
            String setupProvenance,
            double setupSeconds,
            double keyLoadSeconds,
            double proveSeconds,
            double positiveVerifySeconds,
            double negativeVerifySeconds,
            Boolean positiveVerified,
            Boolean negativeInputRejected,
            int circuitTrials,
            List<Double> proveTrialSeconds,
            List<Double> positiveVerifyTrialSeconds,
            List<Double> negativeVerifyTrialSeconds,
            int compressedProofBytes,
            long cardanoVerificationKeyBytes,
            String cardanoArtifactsDirectory,
            long keyStoreBytes,
            long peakObservedHeapBytes,
            long peakObservedRssBytes,
            long peakRssMinusUsedHeapBytes,
            long rssSamples,
            String rssSource) {}
}
