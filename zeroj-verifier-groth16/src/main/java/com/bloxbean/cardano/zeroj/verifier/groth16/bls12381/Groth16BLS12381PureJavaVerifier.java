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
    private static final BigInteger FP = Fp.P;
    private static final BigInteger FR = G1Point.R;

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
            if (!allScalarsInFr(publicInputs)) {
                return VerificationResult.error(
                        VerificationResult.ReasonCode.INVALID_PUBLIC_INPUTS,
                        "Groth16 BLS12-381 public inputs must be canonical scalars in [0, r)");
            }

            // Parse proof points
            G1Point piA = toG1("proof.pi_a", proof.piA());
            G2Point piB = toG2("proof.pi_b", proof.piB());
            G1Point piC = toG1("proof.pi_c", proof.piC());

            // Parse VK points
            G1Point alpha = toG1("vk.alpha", vk.vkAlpha1());
            G2Point beta = toG2("vk.beta", vk.vkBeta2());
            G2Point gamma = toG2("vk.gamma", vk.vkGamma2());
            G2Point delta = toG2("vk.delta", vk.vkDelta2());

            // Compute vk_x = IC[0] + sum(pub_i * IC[i+1])
            G1Point vkX = toG1("vk.IC[0]", vk.ic().get(0));
            for (int i = 0; i < publicInputs.size(); i++) {
                G1Point icPoint = toG1("vk.IC[" + (i + 1) + "]", vk.ic().get(i + 1));
                vkX = vkX.add(icPoint.scalarMul(publicInputs.get(i)));
            }

            // Pairing check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1
            boolean valid = BLS12381Pairing.pairingCheck(
                    new G1Point[]{piA, alpha.negate(), vkX.negate(), piC.negate()},
                    new G2Point[]{piB, beta, gamma, delta});

            return valid ? VerificationResult.cryptoValid()
                    : VerificationResult.proofInvalid("Groth16 BLS12-381 pairing check failed");

        } catch (IllegalArgumentException | UnsupportedOperationException e) {
            return VerificationResult.proofInvalid("Malformed Groth16 BLS12-381 proof or verification key: " + e.getMessage());
        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "Groth16 BLS12-381 verification error: " + e.getMessage());
        }
    }

    private static boolean allScalarsInFr(PublicInputs values) {
        for (BigInteger value : values.values()) {
            if (!scalarInFr(value)) {
                return false;
            }
        }
        return true;
    }

    private static boolean scalarInFr(BigInteger value) {
        return value != null && value.signum() >= 0 && value.compareTo(FR) < 0;
    }

    private static G1Point toG1(String label, List<BigInteger> coords) {
        if (coords.size() != 3) {
            throw new IllegalArgumentException(label + " must have 3 projective coordinates");
        }
        requireFp(label + ".x", coords.get(0));
        requireFp(label + ".y", coords.get(1));
        requireFp(label + ".z", coords.get(2));

        BigInteger z = coords.size() > 2 ? coords.get(2) : BigInteger.ONE;
        G1Point point = G1Point.fromProjective(coords.get(0), coords.get(1), z);
        requireValidNonInfinity(label, point);
        return point;
    }

    private static G2Point toG2(String label, List<List<BigInteger>> coords) {
        if (coords.size() != 3) {
            throw new IllegalArgumentException(label + " must have 3 projective coordinates");
        }
        requireFp2(label + ".x", coords.get(0));
        requireFp2(label + ".y", coords.get(1));
        requireFp2(label + ".z", coords.get(2));

        var z = coords.size() > 2 ? coords.get(2) : List.of(BigInteger.ONE, BigInteger.ZERO);
        G2Point point = G2Point.fromProjective(
                coords.get(0).get(0), coords.get(0).get(1),
                coords.get(1).get(0), coords.get(1).get(1),
                z.get(0), z.get(1));
        requireValidNonInfinity(label, point);
        return point;
    }

    private static void requireFp2(String label, List<BigInteger> values) {
        if (values.size() != 2) {
            throw new IllegalArgumentException(label + " must have 2 Fp coordinates");
        }
        requireFp(label + ".c0", values.get(0));
        requireFp(label + ".c1", values.get(1));
    }

    private static void requireFp(String label, BigInteger value) {
        if (value == null || value.signum() < 0 || value.compareTo(FP) >= 0) {
            throw new IllegalArgumentException(label + " must be in [0, p)");
        }
    }

    private static void requireValidNonInfinity(String label, G1Point point) {
        if (point.isInfinity()) {
            throw new IllegalArgumentException(label + " must not be point at infinity");
        }
        if (!point.isValid()) {
            throw new IllegalArgumentException(label + " must be on curve and in subgroup");
        }
    }

    private static void requireValidNonInfinity(String label, G2Point point) {
        if (point.isInfinity()) {
            throw new IllegalArgumentException(label + " must not be point at infinity");
        }
        if (!point.isValid()) {
            throw new IllegalArgumentException(label + " must be on curve and in subgroup");
        }
    }
}
