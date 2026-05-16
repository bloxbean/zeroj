package com.bloxbean.cardano.zeroj.verifier.groth16.bls12381;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.bls12381.ec.*;
import com.bloxbean.cardano.zeroj.bls12381.field.*;
import com.bloxbean.cardano.zeroj.bls12381.pairing.BLS12381Pairing;

import java.math.BigInteger;
import java.util.List;

/**
 * Pure Java Groth16 verifier for BLS12-381 — no native dependencies.
 *
 * <p>Uses the pure Java BLS12-381 field arithmetic and pairing from
 * {@link com.bloxbean.cardano.zeroj.bls12381}.</p>
 *
 * <p>Verification equation: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1</p>
 *
 * <p>This is the portable alternative to {@link Groth16BLS12381Verifier} which uses the
 * blst native library. Use this when native libraries are not available (GraalVM native-image,
 * Android, restricted environments). For maximum speed, use the blst version.</p>
 */
public class Groth16BLS12381PureJavaVerifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BLS12_381, "groth16-bls12381-java");

    @Override
    public BackendDescriptor descriptor() {
        return DESCRIPTOR;
    }

    @Override
    public VerificationResult verify(ZkProofEnvelope envelope, VerificationMaterial material) {
        try {
            var proof = SnarkjsJsonCodec.parseProof(new String(envelope.proofBytes()));
            var vk = SnarkjsJsonCodec.parseVerificationKey(new String(material.vkBytes()));

            var publicInputs = envelope.publicInputs();
            if (publicInputs.size() != vk.nPublic()) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Expected " + vk.nPublic() + " public inputs, got " + publicInputs.size());
            }

            // Parse proof points
            G1Point piA = toG1(proof.piA());
            G2Point piB = toG2(proof.piB());
            G1Point piC = toG1(proof.piC());

            // Parse VK points
            G1Point alpha = toG1(vk.vkAlpha1());
            G2Point beta = toG2(vk.vkBeta2());
            G2Point gamma = toG2(vk.vkGamma2());
            G2Point delta = toG2(vk.vkDelta2());

            // Compute vk_x = IC[0] + sum(pub_i * IC[i+1])
            G1Point vkX = toG1(vk.ic().get(0));
            for (int i = 0; i < publicInputs.size(); i++) {
                G1Point icPoint = toG1(vk.ic().get(i + 1));
                vkX = vkX.add(icPoint.scalarMul(publicInputs.get(i)));
            }

            // Pairing check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1
            boolean valid = BLS12381Pairing.pairingCheck(
                    new G1Point[]{piA, alpha.negate(), vkX.negate(), piC.negate()},
                    new G2Point[]{piB, beta, gamma, delta});

            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("Groth16 BLS12-381 pairing check failed");

        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "Groth16 BLS12-381 verification error: " + e.getMessage());
        }
    }

    private G1Point toG1(List<BigInteger> coords) {
        BigInteger z = coords.size() > 2 ? coords.get(2) : BigInteger.ONE;
        return G1Point.fromProjective(coords.get(0), coords.get(1), z);
    }

    private G2Point toG2(List<List<BigInteger>> coords) {
        var z = coords.size() > 2 ? coords.get(2) : List.of(BigInteger.ONE, BigInteger.ZERO);
        return G2Point.fromProjective(
                coords.get(0).get(0), coords.get(0).get(1),
                coords.get(1).get(0), coords.get(1).get(1),
                z.get(0), z.get(1));
    }
}
