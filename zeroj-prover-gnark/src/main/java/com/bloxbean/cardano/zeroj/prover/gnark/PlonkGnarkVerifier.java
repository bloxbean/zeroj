package com.bloxbean.cardano.zeroj.prover.gnark;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.codec.GnarkPlonkCodec;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * PlonK BLS12-381 verifier that delegates to gnark's native {@code plonk.Verify()} via FFM.
 * <p>
 * Implements the {@link ZkVerifier} SPI so PlonK proofs can route through
 * {@link com.bloxbean.cardano.zeroj.verifier.core.VerifierOrchestrator}.
 * <p>
 * <b>Requirements:</b>
 * <ul>
 *   <li>gnark native library must be available at runtime</li>
 *   <li>Proof bytes in the {@link ZkProofEnvelope} must be gnark PlonK JSON format
 *       (containing a "binary" field with base64-encoded proof)</li>
 *   <li>{@link VerificationMaterial#vkBytes()} must be gnark binary VK format</li>
 * </ul>
 * <p>
 * <b>Convention:</b> The public witness binary must be stored as a temp file from
 * the envelope's public inputs. This verifier reconstructs the gnark binary witness
 * from the envelope's public inputs using a helper file exported by the test vector generator.
 * For production use, the public witness binary should be stored alongside the VK.
 */
public class PlonkGnarkVerifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.PLONK, CurveId.BLS12_381, "plonk-bls12381-gnark");

    private GnarkLibrary library;

    public PlonkGnarkVerifier() {
        // Lazy init — library loaded on first verify call
    }

    public PlonkGnarkVerifier(GnarkLibrary library) {
        this.library = library;
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            if (library == null) {
                library = new GnarkLibrary();
            }

            // Extract proof base64 from envelope's proof bytes (gnark JSON format)
            String proofJson = new String(envelope.proofBytes(), StandardCharsets.UTF_8);
            String proofBase64 = GnarkPlonkCodec.extractProofBase64(proofJson);

            // Write VK binary to temp file (gnark expects file paths)
            Path vkTempFile = Files.createTempFile("zeroj-plonk-vk-", ".bin");
            Files.write(vkTempFile, material.vkBytes());

            // Write public witness to temp file.
            // Convention: if the VK material has a vkHash, the hash bytes are repurposed
            // to carry the gnark binary public witness (hack for SPI compatibility).
            // Proper solution: extend VerificationMaterial with auxiliary data.
            Path pubWitTempFile = Files.createTempFile("zeroj-plonk-pubwit-", ".bin");
            byte[] pubWitBytes;
            if (material.vkHash().isPresent() && material.vkHash().get().length > 32) {
                // VK hash is overloaded with public witness binary
                pubWitBytes = material.vkHash().get();
            } else {
                // Reconstruct from public inputs (best effort — may not match gnark format exactly)
                pubWitBytes = buildGnarkPublicWitness(envelope.publicInputs(), envelope.curve());
            }
            Files.write(pubWitTempFile, pubWitBytes);

            try {
                String curveStr = envelope.curve() == CurveId.BLS12_381 ? "bls12381" : "bn254";
                boolean valid = library.plonkVerify(curveStr,
                        vkTempFile.toAbsolutePath().toString(),
                        proofBase64,
                        pubWitTempFile.toAbsolutePath().toString());

                return valid ? VerificationResult.cryptoValid()
                        : VerificationResult.proofInvalid("gnark PlonK verification failed");
            } finally {
                Files.deleteIfExists(vkTempFile);
                Files.deleteIfExists(pubWitTempFile);
            }
        } catch (Exception e) {
            return VerificationResult.error(VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "PlonK verification error: " + e.getMessage());
        }
    }

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }

    /**
     * Build gnark binary public witness from public inputs.
     * gnark witness binary format (version 1):
     * - 4 bytes: gnark curve ID (little-endian uint32)
     * - 4 bytes: nbPublic (LE uint32)
     * - 4 bytes: nbSecret (LE uint32) = 0
     * - field elements: each 32 bytes (BN254) or 48 bytes (BLS12-381), big-endian
     */
    private byte[] buildGnarkPublicWitness(PublicInputs inputs, CurveId curve) {
        int fieldSize = curve == CurveId.BLS12_381 ? 48 : 32;
        int curveId = curve == CurveId.BLS12_381 ? 4 : 0; // gnark curve IDs
        int nbPublic = inputs.size();

        byte[] result = new byte[12 + nbPublic * fieldSize];

        // Header (little-endian uint32s)
        writeUint32LE(result, 0, curveId);
        writeUint32LE(result, 4, nbPublic);
        writeUint32LE(result, 8, 0); // nbSecret = 0

        // Field elements
        for (int i = 0; i < nbPublic; i++) {
            byte[] feBytes = inputs.values().get(i).toByteArray();
            // Pad/trim to fieldSize, big-endian
            int offset = 12 + i * fieldSize;
            if (feBytes.length <= fieldSize) {
                System.arraycopy(feBytes, 0, result, offset + fieldSize - feBytes.length, feBytes.length);
            } else {
                // Strip leading zero byte if present
                System.arraycopy(feBytes, feBytes.length - fieldSize, result, offset, fieldSize);
            }
        }

        return result;
    }

    private void writeUint32LE(byte[] buf, int offset, int value) {
        buf[offset] = (byte) (value & 0xFF);
        buf[offset + 1] = (byte) ((value >> 8) & 0xFF);
        buf[offset + 2] = (byte) ((value >> 16) & 0xFF);
        buf[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }
}
