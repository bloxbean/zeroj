package com.bloxbean.cardano.zeroj.examples;

import com.bloxbean.cardano.client.metadata.Metadata;
import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.InMemoryVerificationKeyRegistry;
import com.bloxbean.cardano.zeroj.cardano.AnchorMetadataEncoder;
import com.bloxbean.cardano.zeroj.cardano.AnchorPattern;
import com.bloxbean.cardano.zeroj.cardano.ProofAnchor;
import com.bloxbean.cardano.zeroj.ccl.ZkTransactionHelper;
import com.bloxbean.cardano.zeroj.codec.CanonicalHash;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator;
import com.bloxbean.cardano.zeroj.verifier.core.VerifierRegistry;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Groth16BN254Verifier;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381Verifier;
import com.bloxbean.cardano.zeroj.yaci.protocol.AppProofSubmission;
import com.bloxbean.cardano.zeroj.yaci.protocol.Ed25519Signer;
import com.bloxbean.cardano.zeroj.yaci.protocol.SubmissionHash;
import com.bloxbean.cardano.zeroj.yaci.protocol.SubmissionResult;
import com.bloxbean.cardano.zeroj.yaci.zk.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.util.List;

/**
 * ZeroJ End-to-End Demo
 * =====================
 *
 * This demo shows the complete flow of ZeroJ — from external proof generation
 * to Cardano L1 anchoring — in a single runnable program.
 *
 * The scenario: A DeFi protocol uses ZK proofs to verify off-chain balance transfers.
 * - A user computes a balance transfer off-chain
 * - A ZK proof is generated externally (snarkjs/circom)
 * - The proof is submitted to a network of Yaci verifier nodes
 * - Each node verifies the proof WITHOUT re-executing the computation
 * - The verified result is anchored on Cardano L1
 *
 * This is the core value proposition of ZeroJ:
 *   "Prove once, verify everywhere, settle on Cardano."
 */
public class EndToEndDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("=".repeat(70));
        System.out.println("  ZeroJ End-to-End Demo");
        System.out.println("  Prove once, verify everywhere, settle on Cardano");
        System.out.println("=".repeat(70));
        System.out.println();

        // ============================================================
        // STEP 1: Load a real snarkjs-generated Groth16 proof
        // ============================================================
        // In production, this proof would be generated externally by
        // the user's off-chain application using circom + snarkjs.
        // The circuit proves: a * b = c (public: [c=33, a=3], private: b=11)

        System.out.println("[Step 1] Loading externally-generated Groth16/BN254 proof...");
        String proofJson = loadResource("/test-vectors/groth16-bn254/proof.json");
        String vkJson = loadResource("/test-vectors/groth16-bn254/verification_key.json");
        String publicJson = loadResource("/test-vectors/groth16-bn254/public.json");

        var proof = SnarkjsJsonCodec.parseProof(proofJson);
        var vk = SnarkjsJsonCodec.parseVerificationKey(vkJson);
        var publicInputs = SnarkjsJsonCodec.parsePublicInputs(publicJson);

        System.out.println("  Proof system: " + proof.protocol() + " / " + proof.curve());
        System.out.println("  Public inputs: " + publicInputs.values());
        System.out.println("  (Circuit: a * b = c, proving 3 * 11 = 33 without revealing b=11)");
        System.out.println();

        // ============================================================
        // STEP 2: Set up the ZeroJ verification infrastructure
        // ============================================================
        // This runs on each Yaci node. Nodes never see the private input (b=11).

        System.out.println("[Step 2] Setting up ZeroJ verifier (runs on each Yaci node)...");

        // Register verification backends
        var verifierRegistry = VerifierRegistry.empty();
        verifierRegistry.register(new Groth16BN254Verifier());    // Pure Java
        verifierRegistry.register(new Groth16BLS12381Verifier()); // Native blst
        System.out.println("  Registered backends: Groth16/BN254 (pure Java), Groth16/BLS12-381 (blst)");

        // Register the verification key
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkHash = sha256(vkBytes);
        var vkRegistry = new InMemoryVerificationKeyRegistry();
        var material = VerificationMaterial.of(vkBytes, ProofSystemId.GROTH16, CurveId.BN254,
                new CircuitId("multiplier"), vkHash);
        vkRegistry.register(material);

        var orchestrator = new VerifierOrchestrator(verifierRegistry, vkRegistry);
        System.out.println("  VK registered: " + hex(vkHash).substring(0, 16) + "...");
        System.out.println();

        // ============================================================
        // STEP 3: Standalone proof verification
        // ============================================================
        // The simplest use case — just verify a proof in Java.

        System.out.println("[Step 3] Verifying proof (standalone)...");
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(proofJson, vkJson, publicJson,
                new CircuitId("multiplier"));
        var result = orchestrator.verify(envelope, material);

        System.out.println("  Proof valid: " + result.proofValid());
        System.out.println("  Canonical hash: " + hex(CanonicalHash.hash(envelope)).substring(0, 16) + "...");
        assert result.proofValid() : "Proof should be valid!";
        System.out.println();

        // ============================================================
        // STEP 4: Submit as a proof-backed state transition (Yaci protocol)
        // ============================================================
        // The submitter signs the transition and submits to the Yaci network.
        // The 6-stage pipeline validates everything: signature, authorization,
        // circuit allowlist, cryptographic proof, state root chain, replay protection.

        System.out.println("[Step 4] Submitting proof-backed state transition to Yaci...");

        // Set up identity
        KeyPair submitterKeys = Ed25519Signer.generateKeyPair();
        String submitterId = "alice";

        // Set up policy infrastructure
        var submitterReg = new InMemorySubmitterRegistry();
        submitterReg.register(submitterId, submitterKeys.getPublic(), "defi-app");

        var circuitAllowlist = new InMemoryCircuitAllowlist();
        circuitAllowlist.allow("multiplier", "v1");

        var stateRootStore = new InMemoryStateRootStore();
        byte[] genesisRoot = sha256("genesis-state".getBytes());
        stateRootStore.initialize("defi-app", genesisRoot);

        var sequenceTracker = new InMemorySequenceTracker();
        var nullifierStore = new InMemoryNullifierStore();

        var pipeline = new SubmissionIngestionPipeline(
                orchestrator, vkRegistry, submitterReg, circuitAllowlist,
                stateRootStore, sequenceTracker, nullifierStore);

        // Build the submission
        byte[] newStateRoot = sha256("state-after-transfer".getBytes());
        var unsigned = AppProofSubmission.builder()
                .appId("defi-app")
                .proofSystem(ProofSystemId.GROTH16)
                .curve(CurveId.BN254)
                .circuitId("multiplier")
                .circuitVersion("v1")
                .prevStateRoot(genesisRoot)
                .newStateRoot(newStateRoot)
                .publicInputs(List.of(BigInteger.valueOf(33), BigInteger.valueOf(3)))
                .proofBytes(proofJson.getBytes(StandardCharsets.UTF_8))
                .vkHash(vkHash)
                .submitterId(submitterId)
                .submitterSignature(new byte[64])
                .sequence(1)
                .build();

        // Sign with Ed25519
        byte[] submissionHash = SubmissionHash.compute(unsigned);
        byte[] signature = Ed25519Signer.sign(submissionHash, submitterKeys.getPrivate());

        var submission = AppProofSubmission.builder()
                .appId(unsigned.appId()).proofSystem(unsigned.proofSystem())
                .curve(unsigned.curve()).circuitId(unsigned.circuitId())
                .circuitVersion(unsigned.circuitVersion())
                .prevStateRoot(unsigned.prevStateRoot())
                .newStateRoot(unsigned.newStateRoot())
                .publicInputs(unsigned.publicInputs())
                .proofBytes(unsigned.proofBytes()).vkHash(unsigned.vkHash())
                .submitterId(unsigned.submitterId())
                .submitterSignature(signature)
                .sequence(unsigned.sequence())
                .build();

        System.out.println("  Submitter: " + submitterId);
        System.out.println("  App: " + submission.appId());
        System.out.println("  Circuit: " + submission.circuitId() + "/" + submission.circuitVersion());
        System.out.println("  Sequence: " + submission.sequence());

        // Process through 6-stage pipeline
        SubmissionResult subResult = pipeline.process(submission);

        System.out.println("  Pipeline stages: syntactic -> signature -> circuit -> crypto -> policy -> accept");
        System.out.println("  Result: " + (subResult.accepted() ? "ACCEPTED" : "REJECTED: " + subResult.reason().orElse(null)));
        assert subResult.accepted() : "Submission should be accepted!";
        System.out.println();

        // ============================================================
        // STEP 5: Anchor on Cardano L1
        // ============================================================
        // After verification, anchor the result on Cardano for settlement.

        System.out.println("[Step 5] Anchoring verified result on Cardano L1...");

        byte[] proofHash = sha256(proofJson.getBytes(StandardCharsets.UTF_8));

        // Build anchor metadata
        Metadata metadata = ZkTransactionHelper.anchorFullRef(
                        newStateRoot, proofHash, "multiplier/v1", vkHash)
                .buildMetadata();

        byte[] metadataCbor = metadata.serialize();

        System.out.println("  Anchor pattern: FULL_VERIFICATION_REF");
        System.out.println("  State root: " + hex(newStateRoot).substring(0, 16) + "...");
        System.out.println("  Proof hash: " + hex(proofHash).substring(0, 16) + "...");
        System.out.println("  VK hash:    " + hex(vkHash).substring(0, 16) + "...");
        System.out.println("  Metadata CBOR: " + metadataCbor.length + " bytes");
        System.out.println("  CIP-10 label: " + AnchorMetadataEncoder.DEFAULT_LABEL);
        System.out.println();

        // ============================================================
        // STEP 6: Demonstrate security — replay attack is rejected
        // ============================================================
        System.out.println("[Step 6] Security demo — replay attack...");

        // Try to replay the same submission (same sequence number)
        SubmissionResult replayResult = pipeline.process(submission);
        System.out.println("  Replaying same submission...");
        System.out.println("  Result: " + (replayResult.accepted() ? "ACCEPTED (BAD!)" : "REJECTED"));
        System.out.println("  Stage: " + replayResult.stage());
        System.out.println("  Reason: " + replayResult.reason().orElse(null));
        assert !replayResult.accepted() : "Replay should be rejected!";
        System.out.println();

        // ============================================================
        // DONE
        // ============================================================
        System.out.println("=".repeat(70));
        System.out.println("  Demo complete!");
        System.out.println();
        System.out.println("  What happened:");
        System.out.println("  1. Proof generated EXTERNALLY (snarkjs/circom)");
        System.out.println("  2. Verified in JAVA without re-executing the computation");
        System.out.println("  3. Submitted with Ed25519 signature to Yaci network");
        System.out.println("  4. 6-stage validation: auth + crypto + policy");
        System.out.println("  5. Anchored on Cardano L1 as CIP-10 metadata");
        System.out.println("  6. Replay attack automatically rejected");
        System.out.println();
        System.out.println("  ZeroJ: Prove once, verify everywhere, settle on Cardano.");
        System.out.println("=".repeat(70));
    }

    private static String loadResource(String path) {
        try (var in = EndToEndDemo.class.getResourceAsStream(path)) {
            if (in == null) throw new RuntimeException("Resource not found: " + path);
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException(e);
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
