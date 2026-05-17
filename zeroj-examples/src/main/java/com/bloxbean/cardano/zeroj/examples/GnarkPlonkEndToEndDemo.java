package com.bloxbean.cardano.zeroj.examples;

import com.bloxbean.cardano.client.metadata.Metadata;
import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.cardano.AnchorMetadataEncoder;
import com.bloxbean.cardano.zeroj.ccl.ZkTransactionHelper;
import com.bloxbean.cardano.zeroj.codec.GnarkPlonkCodec;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

/**
 * ZeroJ Gnark PlonK End-to-End Demo
 * ===================================
 *
 * This demo shows the complete gnark PlonK artifact flow using Java (no Node.js,
 * no CLI tools):
 *
 *   1. gnark FFM: setup + prove + verify (in-process, via Go native library)
 *   2. ZeroJ: normalize the proof artifact and hash it
 *   3. Cardano: anchor the verified result on L1
 *
 * Circuit: Multiplier (X * Y = Z) on BLS12-381
 * Witness: X=3, Y=11, Z=33 (public: Z=33)
 *
 * Prerequisites:
 *   - gnark native library built: cd zeroj-prover-gnark/gnark-wrapper && make build
 *   - Test vectors generated: the pre-generated vectors in zeroj-test-vectors are used
 *
 * Pure Java PlonK verification currently consumes structured snarkjs/ZeroJ proof
 * JSON, not gnark's opaque binary PlonK proof JSON. Gnark binary proofs should be
 * verified with gnark until a dedicated adapter is added.
 */
public class GnarkPlonkEndToEndDemo {

    public static void main(String[] args) throws Exception {
        System.out.println("=".repeat(70));
        System.out.println("  ZeroJ Gnark PlonK End-to-End Demo");
        System.out.println("  gnark proves/verifies → ZeroJ anchors");
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
        boolean gnarkVerified;

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

            var pubSignals = proveResult.publicSignals();

            System.out.println("  Proof generated: " + proofBase64.length() + " chars (base64)");
            System.out.println("  Protocol: " + proveResult.protocol());
            System.out.println("  Public inputs: " + pubSignals);

            // Verify with gnark native (sanity check)
            gnarkVerified = prover.plonkVerify("bls12381",
                    vkBinPath, proofBase64, pubWitnessPath);
            System.out.println("  gnark native verify: " + (gnarkVerified ? "PASS" : "FAIL"));
            assert gnarkVerified : "gnark native verification failed!";
        }
        System.out.println();

        // ============================================================
        // STEP 2: Normalize the gnark artifact for anchoring
        // ============================================================
        // The proof was generated and verified by gnark. ZeroJ keeps the proof
        // as a typed artifact for hashing and anchoring. Do not route gnark's
        // opaque binary PlonK JSON into the snarkjs-style pure Java verifier.

        System.out.println("[Step 2] ZeroJ proof artifact metadata...");
        byte[] vkBytes = vkJson.getBytes(StandardCharsets.UTF_8);
        byte[] vkHash = sha256(vkBytes);

        System.out.println("  Proof system: PlonK / BLS12-381");
        System.out.println("  Proof format: gnark-plonk-json");
        System.out.println("  Verification: gnark native " + (gnarkVerified ? "PASS" : "FAIL"));
        System.out.println("  Pure Java verifier: use structured snarkjs/ZeroJ PlonK proof JSON");
        System.out.println("  VK hash: " + hex(vkHash).substring(0, 16) + "...");
        System.out.println();

        // ============================================================
        // STEP 3: Anchor on Cardano L1
        // ============================================================
        byte[] newStateRoot = sha256("state-after-proof".getBytes());
        byte[] proofHash = sha256(proofJson.getBytes(StandardCharsets.UTF_8));
        Metadata metadata = ZkTransactionHelper.anchorFullRef(
                        newStateRoot, proofHash, "multiplier-bls/v1", vkHash)
                .buildMetadata();
        byte[] metadataCbor = metadata.serialize();

        System.out.println("[Step 3] Anchoring gnark-verified result on Cardano L1...");
        System.out.println("  Anchor pattern: FULL_VERIFICATION_REF");
        System.out.println("  State root: " + hex(newStateRoot).substring(0, 16) + "...");
        System.out.println("  Proof hash: " + hex(proofHash).substring(0, 16) + "...");
        System.out.println("  VK hash:    " + hex(vkHash).substring(0, 16) + "...");
        System.out.println("  Metadata CBOR: " + metadataCbor.length + " bytes");
        System.out.println("  CIP-10 label: " + AnchorMetadataEncoder.DEFAULT_LABEL);
        System.out.println();

        // ============================================================
        // DONE
        // ============================================================
        System.out.println("=".repeat(70));
        System.out.println("  Demo complete!");
        System.out.println();
        System.out.println("  What happened (all in one JVM process):");
        System.out.println("  1. gnark FFM: PlonK setup + prove + verify (Go native, in-process)");
        System.out.println("  2. ZeroJ: typed proof artifact hashed for anchoring");
        System.out.println("  3. Cardano:   anchor metadata built for L1 settlement");
        System.out.println();
        System.out.println("  External tools needed: NONE at runtime");
        System.out.println("  Native libs: gnark .dylib/.so (proving + gnark binary verification)");
        System.out.println("  Verification: pure Java path is available for structured PlonK proof JSON");
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
