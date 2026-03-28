package com.bloxbean.cardano.zeroj.examples;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.codec.GnarkPlonkCodec;
import com.bloxbean.cardano.zeroj.ingestion.*;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.submission.AppProofSubmission;
import com.bloxbean.cardano.zeroj.submission.Ed25519Signer;
import com.bloxbean.cardano.zeroj.submission.SubmissionHash;
import com.bloxbean.cardano.zeroj.submission.SubmissionResult;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.plonk.PlonkBN254Verifier;
import com.bloxbean.cardano.zeroj.verifier.plonk.PlonkBLS12381Verifier;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

/**
 * ZeroJ Gnark PlonK End-to-End Demo
 * ===================================
 *
 * This demo shows the complete ZK flow using ONLY Java (no Node.js, no CLI tools):
 *
 *   1. gnark FFM: setup + prove (in-process, via Go native library)
 *   2. Pure Java: verify (no native deps for verification)
 *   3. Pipeline: 6-stage validation with governance
 *   4. Cardano: anchor on L1
 *
 * Circuit: Multiplier (X * Y = Z) on BLS12-381
 * Witness: X=3, Y=11, Z=33 (public: Z=33)
 *
 * Prerequisites:
 *   - gnark native library built: cd zeroj-prover-gnark/gnark-wrapper && make build
 *   - Test vectors generated: the pre-generated vectors in zeroj-test-vectors are used
 *
 * This demonstrates: gnark proves → pure Java verifies → Cardano anchors.
 * All in one JVM process.
 */
public class GnarkPlonkEndToEndDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("=".repeat(70));
        System.out.println("  ZeroJ Gnark PlonK End-to-End Demo");
        System.out.println("  gnark proves → pure Java verifies → Cardano anchors");
        System.out.println("=".repeat(70));
        System.out.println();

        // ============================================================
        // STEP 1: Setup and Prove with gnark (in-process via FFM)
        // ============================================================
        // gnark runs inside the JVM via Foreign Function & Memory API.
        // No external processes, no CLI tools, no Node.js.

        System.out.println("[Step 1] gnark PlonK setup + prove (in-process via FFM)...");

        // Load pre-generated test vectors (circuit + witness)
        // In production, these come from the gnark circuit compilation step.
        Path circuitPath = extractResource("/test-vectors/plonk-bls12381/circuit.scs");
        Path witnessPath = extractResource("/test-vectors/plonk-bls12381/witness.bin");
        Path vkBinPath = extractResource("/test-vectors/plonk-bls12381/verification_key.bin");
        Path pubWitnessPath = extractResource("/test-vectors/plonk-bls12381/public_witness.bin");

        String proofBase64;
        String proofJson;
        String vkJson;
        String publicJson;

        try (var prover = new GnarkProver()) {
            System.out.println("  gnark version: " + prover.gnarkVersion());

            // PlonK setup: generates proving key + verification key
            var setupResult = prover.plonkSetup("bls12381", circuitPath);
            System.out.println("  Setup complete: PK at " + setupResult.pkPath());
            vkJson = setupResult.vkJson();

            // PlonK prove: generates proof from circuit + witness
            var proveResult = prover.plonkProveRaw("bls12381", circuitPath,
                    Path.of(setupResult.pkPath()), witnessPath);

            proofJson = proveResult.proofJson();
            proofBase64 = GnarkPlonkCodec.extractProofBase64(proofJson);

            // Build public.json from the public signals
            var pubSignals = proveResult.publicSignals();
            var pubJsonBuilder = new StringBuilder("[");
            for (int i = 0; i < pubSignals.size(); i++) {
                if (i > 0) pubJsonBuilder.append(",");
                pubJsonBuilder.append("\"").append(pubSignals.get(i)).append("\"");
            }
            publicJson = pubJsonBuilder.append("]").toString();

            System.out.println("  Proof generated: " + proofBase64.length() + " chars (base64)");
            System.out.println("  Protocol: " + proveResult.protocol());
            System.out.println("  Public inputs: " + pubSignals);

            // Verify with gnark native (sanity check)
            boolean gnarkVerified = prover.plonkVerify("bls12381",
                    vkBinPath, proofBase64, pubWitnessPath);
            System.out.println("  gnark native verify: " + (gnarkVerified ? "PASS" : "FAIL"));
            assert gnarkVerified : "gnark native verification failed!";
        }
        System.out.println();

        // ============================================================
        // STEP 2: Verify with Pure Java (no native library needed)
        // ============================================================
        // The proof was generated by gnark, but we verify it with pure Java.
        // This demonstrates that the verification side has ZERO native dependencies.

        System.out.println("[Step 2] Pure Java verification (zero native deps)...");

        // Register pure Java PlonK verifiers
        var verifierRegistry = VerifierRegistry.empty();
        verifierRegistry.register(new PlonkBLS12381Verifier()); // Pure Java
        verifierRegistry.register(new PlonkBN254Verifier());     // Pure Java

        // Build envelope from gnark proof with witness in metadata
        byte[] pubWitnessBytes = Files.readAllBytes(pubWitnessPath);
        var envelope = GnarkPlonkCodec.toEnvelopeWithWitness(
                proofJson, vkJson, publicJson,
                new CircuitId("multiplier-bls"), pubWitnessBytes);

        // Register VK
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkHash = sha256(vkBytes);
        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of(vkBytes, ProofSystemId.PLONK, CurveId.BLS12_381,
                new CircuitId("multiplier-bls"), vkHash);
        vkRegistry.register(material);

        var orchestrator = new VerifierOrchestrator(verifierRegistry, vkRegistry);
        var result = orchestrator.verify(envelope, material);

        System.out.println("  Proof system: PlonK / BLS12-381");
        System.out.println("  Verifier: pure Java (no gnark, no blst)");
        System.out.println("  Proof valid: " + result.proofValid());
        System.out.println("  VK hash: " + hex(vkHash).substring(0, 16) + "...");
        System.out.println();

        // ============================================================
        // STEP 3: Submit through 6-stage governance pipeline
        // ============================================================
        System.out.println("[Step 3] Submitting through governance pipeline...");

        KeyPair submitterKeys = Ed25519Signer.generateKeyPair();
        String submitterId = "gnark-prover-node";

        var submitterReg = new InMemorySubmitterRegistry();
        submitterReg.register(submitterId, submitterKeys.getPublic(), "zk-app");

        var circuitRegistry = new InMemoryCircuitRegistry();
        circuitRegistry.register(CircuitRegistry.CircuitVersionInfo.active("multiplier-bls", "v1"));

        var stateRootStore = new InMemoryStateRootStore();
        byte[] genesisRoot = sha256("genesis".getBytes());
        stateRootStore.initialize("zk-app", genesisRoot);

        var auditLog = new InMemoryAuditLog();
        var pipeline = new SubmissionIngestionPipeline(
                orchestrator, vkRegistry, submitterReg, circuitRegistry,
                stateRootStore, new InMemorySequenceTracker(), new InMemoryNullifierStore(),
                auditLog);

        // Build submission
        var publicInputs = GnarkPlonkCodec.parsePublicInputs(publicJson);
        byte[] newStateRoot = sha256("state-after-proof".getBytes());
        var unsigned = AppProofSubmission.builder()
                .appId("zk-app").proofSystem(ProofSystemId.PLONK).curve(CurveId.BLS12_381)
                .circuitId("multiplier-bls").circuitVersion("v1")
                .prevStateRoot(genesisRoot).newStateRoot(newStateRoot)
                .publicInputs(publicInputs.values())
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .vkHash(vkHash).submitterId(submitterId)
                .submitterSignature(new byte[64]).sequence(1).build();

        byte[] sig = Ed25519Signer.sign(SubmissionHash.compute(unsigned), submitterKeys.getPrivate());
        var submission = AppProofSubmission.builder()
                .appId(unsigned.appId()).proofSystem(unsigned.proofSystem())
                .curve(unsigned.curve()).circuitId(unsigned.circuitId())
                .circuitVersion(unsigned.circuitVersion())
                .prevStateRoot(unsigned.prevStateRoot()).newStateRoot(unsigned.newStateRoot())
                .publicInputs(unsigned.publicInputs())
                .proofBytes(unsigned.proofBytes()).vkHash(unsigned.vkHash())
                .submitterId(unsigned.submitterId()).submitterSignature(sig)
                .sequence(unsigned.sequence()).build();

        SubmissionResult subResult = pipeline.process(submission);
        System.out.println("  Pipeline: syntactic → signature → circuit → crypto → policy → accept");
        System.out.println("  Result: " + (subResult.accepted() ? "ACCEPTED" : "REJECTED: " + subResult.reason().orElse(null)));
        System.out.println("  Audit entries: " + auditLog.count());
        System.out.println();

        // ============================================================
        // DONE
        // ============================================================
        System.out.println("=".repeat(70));
        System.out.println("  Demo complete!");
        System.out.println();
        System.out.println("  What happened (all in one JVM process):");
        System.out.println("  1. gnark FFM: PlonK setup + prove (Go native, in-process)");
        System.out.println("  2. Pure Java: PlonK verify (zero native deps)");
        System.out.println("  3. Pipeline:  6-stage governance validation");
        System.out.println("  4. Ready:     for Cardano L1 anchoring");
        System.out.println();
        System.out.println("  External tools needed: NONE at runtime");
        System.out.println("  Native libs: gnark .dylib/.so (proving only)");
        System.out.println("  Verification: 100% pure Java");
        System.out.println("=".repeat(70));
    }

    private static Path extractResource(String resource) throws Exception {
        try (var in = GnarkPlonkEndToEndDemo.class.getResourceAsStream(resource)) {
            if (in == null) throw new RuntimeException("Resource not found: " + resource);
            Path tmp = Files.createTempFile("zeroj-", resource.substring(resource.lastIndexOf('/')));
            Files.write(tmp, in.readAllBytes());
            tmp.toFile().deleteOnExit();
            return tmp;
        }
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private static String hex(byte[] bytes) {
        var sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
