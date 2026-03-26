package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.codec.SnarkjsProof;
import com.bloxbean.cardano.zeroj.codec.SnarkjsVerificationKey;

import java.math.BigInteger;

/**
 * Groth16 verifier for BN254 curve using pure Java pairing arithmetic.
 *
 * <p>Verification algorithm:</p>
 * <ol>
 *   <li>Compute vk_x = IC[0] + sum(pub_i * IC[i+1]) — public input linear combination</li>
 *   <li>Check: e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)</li>
 *   <li>Equivalently: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1</li>
 * </ol>
 */
public class Groth16BN254Verifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BN254, "groth16-bn254-java");

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            // Parse the snarkjs-format proof and VK from bytes
            var proof = SnarkjsJsonCodec.parseProof(new String(envelope.proofBytes()));
            var vk = SnarkjsJsonCodec.parseVerificationKey(new String(material.vkBytes()));

            // Validate public input count
            var publicInputs = envelope.publicInputs();
            if (publicInputs.size() != vk.nPublic()) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Expected " + vk.nPublic() + " public inputs, got " + publicInputs.size());
            }

            // Parse curve points
            var piA = parseG1(proof.piA());
            var piB = parseG2(proof.piB());
            var piC = parseG1(proof.piC());

            var alpha = parseG1(vk.vkAlpha1());
            var beta = parseG2(vk.vkBeta2());
            var gamma = parseG2(vk.vkGamma2());
            var delta = parseG2(vk.vkDelta2());

            // Compute vk_x = IC[0] + sum(pub_i * IC[i+1])
            var vkX = parseG1(vk.ic().get(0));
            for (int i = 0; i < publicInputs.size(); i++) {
                var icPoint = parseG1(vk.ic().get(i + 1));
                vkX = vkX.add(icPoint.scalarMul(publicInputs.get(i)));
            }

            // Pairing check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1
            boolean valid = BN254Pairing.pairingCheck(
                    new G1Point[]{piA, alpha.negate(), vkX.negate(), piC.negate()},
                    new G2Point[]{piB, beta, gamma, delta}
            );

            if (valid) {
                return VerificationResult.cryptoValid();
            } else {
                return VerificationResult.proofInvalid("Pairing check failed");
            }
        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "Verification error: " + e.getMessage());
        }
    }

    private static G1Point parseG1(java.util.List<BigInteger> coords) {
        return G1Point.fromProjective(coords.get(0), coords.get(1), coords.get(2));
    }

    private static G2Point parseG2(java.util.List<java.util.List<BigInteger>> coords) {
        return G2Point.fromProjective(
                coords.get(0).get(0), coords.get(0).get(1),
                coords.get(1).get(0), coords.get(1).get(1),
                coords.get(2).get(0), coords.get(2).get(1));
    }
}
