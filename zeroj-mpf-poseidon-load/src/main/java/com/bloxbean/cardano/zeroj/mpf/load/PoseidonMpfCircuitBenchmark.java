package com.bloxbean.cardano.zeroj.mpf.load;

import com.bloxbean.cardano.zeroj.api.CurveId;
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
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfHash;
import com.bloxbean.cardano.zeroj.mpf.poseidon.PoseidonMpfValueCommitment;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec.ProverToCardano;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
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
            String fingerprint = Groth16Pipeline.fingerprint(
                    constraints, wires, publicInputCount);
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
                try (keys) {
                    long proveStarted = System.nanoTime();
                    Groth16ProofBLS381 proof = keys.prove(witness.values(), compiled.constraints());
                    proveSeconds = secondsSince(proveStarted);
                    ProofVerification verification = verifyProof(keys, proof, publicInputs);
                    positiveVerified = verification.positiveVerified();
                    negativeRejected = verification.negativeRejected();
                    positiveVerifySeconds = verification.positiveSeconds();
                    negativeVerifySeconds = verification.negativeSeconds();
                    compressedProofBytes = verification.compressedBytes();
                    ArtifactStats artifacts = writeCardanoArtifacts(keys, proof, rootInput);
                    cardanoVerificationKeyBytes = artifacts.verificationKeyBytes();
                    cardanoArtifactsDirectory = artifacts.directory();
                }
            } else {
                Path constraintCache = options.keysDir().resolve(Groth16Pipeline.R1CS_CACHE);
                if (options.setupMode() == LoadOptions.SetupMode.STORE) {
                    requireBenchmarkSetupOptIn();
                    requireEmptyOrMissing(options.keysDir());
                    var pipelineCircuit = new Groth16Pipeline.Compiled(
                            compiled.flat(), constraints, wires, publicInputCount);
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
                        long proveStarted = System.nanoTime();
                        Groth16ProofBLS381 proof = Groth16Pipeline.prove(
                                keys,
                                constraintCache,
                                fingerprint,
                                () -> { throw new IllegalStateException("Matching R1CS cache disappeared"); },
                                witness::values,
                                0,
                                ProverBackend.PURE_JAVA);
                        proveSeconds = secondsSince(proveStarted);
                        ProofVerification verification = verifyProof(keys, proof, publicInputs);
                        positiveVerified = verification.positiveVerified();
                        negativeRejected = verification.negativeRejected();
                        positiveVerifySeconds = verification.positiveSeconds();
                        negativeVerifySeconds = verification.negativeSeconds();
                        compressedProofBytes = verification.compressedBytes();
                        ArtifactStats artifacts = writeCardanoArtifacts(keys, proof, rootInput);
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
                    options.maxForkPrefixChunks(),
                    constraints,
                    wires,
                    publicInputCount,
                    privateInputCount,
                    fingerprint,
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
                    compressedProofBytes,
                    cardanoVerificationKeyBytes,
                    cardanoArtifactsDirectory,
                    keyStoreBytes,
                    heap.peakBytes());
            files.writeReportSection("circuit", result);
            return result;
        }
    }

    private CompiledCircuit compileCircuit() {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonMpfInclusionCircuit.build(
                options.maxSteps(), options.maxForkPrefixChunks());
        double buildSeconds = secondsSince(buildStarted);
        long compileStarted = System.nanoTime();
        var r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        double compileSeconds = secondsSince(compileStarted);
        return new CompiledCircuit(
                r1cs.flat(), r1cs.constraints(), r1cs.numConstraints(), r1cs.numWires(),
                r1cs.numPublicInputs(), r1cs.numPrivateInputs(), buildSeconds, compileSeconds);
    }

    private BoxedWitness calculateBoxedWitness(Map<String, List<BigInteger>> inputs, int expectedWires) {
        long buildStarted = System.nanoTime();
        var circuit = PoseidonMpfInclusionCircuit.build(
                options.maxSteps(), options.maxForkPrefixChunks());
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
        var circuit = PoseidonMpfInclusionCircuit.build(
                options.maxSteps(), options.maxForkPrefixChunks());
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
            BigInteger publicRoot) throws IOException {
        var compressedVk = ProverToCardano.compressVk(keys);
        var compressedProof = ProverToCardano.compressProof(proof);
        files.writeCardanoArtifact("proof-a.g1", compressedProof.piA());
        files.writeCardanoArtifact("proof-b.g2", compressedProof.piB());
        files.writeCardanoArtifact("proof-c.g1", compressedProof.piC());
        files.writeCardanoArtifact("vk-alpha.g1", compressedVk.alpha());
        files.writeCardanoArtifact("vk-beta.g2", compressedVk.beta());
        files.writeCardanoArtifact("vk-gamma.g2", compressedVk.gamma());
        files.writeCardanoArtifact("vk-delta.g2", compressedVk.delta());
        for (int i = 0; i < compressedVk.ic().size(); i++) {
            files.writeCardanoArtifact("vk-ic-" + i + ".g1", compressedVk.ic().get(i));
        }
        files.writeCardanoArtifact("public-input-root.bin", PoseidonMpfHash.toDigestBytes(publicRoot));
        long verificationKeyBytes = compressedVk.alpha().length
                + compressedVk.beta().length
                + compressedVk.gamma().length
                + compressedVk.delta().length
                + compressedVk.ic().stream().mapToLong(value -> value.length).sum();
        return new ArtifactStats(files.cardanoArtifactsDir().toString(), verificationKeyBytes);
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

    private record ArtifactStats(String directory, long verificationKeyBytes) {}

    public record CircuitResult(
            String startedAt,
            String completedAt,
            long datasetIndex,
            int observedProofSteps,
            int maxSteps,
            int maxForkPrefixChunks,
            int constraints,
            int wires,
            int publicInputs,
            int privateInputs,
            String fingerprint,
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
            int compressedProofBytes,
            long cardanoVerificationKeyBytes,
            String cardanoArtifactsDirectory,
            long keyStoreBytes,
            long peakObservedHeapBytes) {}
}
