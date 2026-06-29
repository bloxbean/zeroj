package com.bloxbean.cardano.zeroj.verifier.groth16.bls12381;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.backend.spi.BackendDescriptor;
import com.bloxbean.cardano.zeroj.backend.spi.ZkVerifier;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.codec.SnarkjsProof;
import com.bloxbean.cardano.zeroj.codec.SnarkjsVerificationKey;
import supranational.blst.*;

import java.math.BigInteger;
import java.util.List;

/**
 * Groth16 verifier for BLS12-381 curve using the blst native library.
 *
 * <p>Uses {@code foundation.icon:blst-java} for pairing arithmetic.
 * Same approach as julc-bls but focused on Groth16 verification.</p>
 *
 * <p>Verification: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1</p>
 */
public class Groth16BLS12381Verifier implements ZkVerifier {

    private static final BackendDescriptor DESCRIPTOR =
            new BackendDescriptor(ProofSystemId.GROTH16, CurveId.BLS12_381, "groth16-bls12381-blst");

    /** BLS12-381 base field prime p. */
    private static final BigInteger BLS12_381_P = new BigInteger(
            "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787");

    /** BLS12-381 scalar field order r. */
    private static final BigInteger BLS12_381_R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    /** Size of an Fp element in bytes (381 bits -> 48 bytes). */
    private static final int FP_SIZE = 48;

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

            // Parse points from snarkjs JSON to blst format
            var piA = decodeG1("proof.pi_a", proof.piA());
            var piB = decodeG2("proof.pi_b", proof.piB());
            var piC = decodeG1("proof.pi_c", proof.piC());

            var alpha = decodeG1("vk.alpha", vk.vkAlpha1());
            var beta = decodeG2("vk.beta", vk.vkBeta2());
            var gamma = decodeG2("vk.gamma", vk.vkGamma2());
            var delta = decodeG2("vk.delta", vk.vkDelta2());

            // Compute vk_x = IC[0] + sum(pub_i * IC[i+1])
            P1 vkX = new P1(decodeG1("vk.IC[0]", vk.ic().get(0)));
            for (int i = 0; i < publicInputs.size(); i++) {
                var icPoint = new P1(decodeG1("vk.IC[" + (i + 1) + "]", vk.ic().get(i + 1)));
                vkX.add(icPoint.mult(publicInputs.get(i)).to_affine());
            }

            // Negate A for the pairing check: e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
            // => e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) should be... no.
            // Standard check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1

            // Negate the points that need negation
            var negAlpha = new P1(alpha);
            negAlpha.neg();

            var negVkX = vkX.dup();
            negVkX.neg();

            var negC = new P1(piC);
            negC.neg();

            // Compute multi-pairing
            var pairingAB = new PT(piA, piB);
            var pairingAlphaBeta = new PT(negAlpha.to_affine(), beta);
            var pairingVkxGamma = new PT(negVkX.to_affine(), gamma);
            var pairingCDelta = new PT(negC.to_affine(), delta);

            // Multiply all miller loop results
            var mlResult = pairingAB.dup();
            mlResult.mul(pairingAlphaBeta);
            mlResult.mul(pairingVkxGamma);
            mlResult.mul(pairingCDelta);

            // Final verification
            boolean valid = PT.finalverify(mlResult, new PT(new P1_Affine(), new P2_Affine()));

            if (valid) {
                return VerificationResult.cryptoValid();
            } else {
                return VerificationResult.proofInvalid("Pairing check failed");
            }
        } catch (IllegalArgumentException | UnsupportedOperationException e) {
            return VerificationResult.proofInvalid("Malformed Groth16 BLS12-381 proof or verification key: " + e.getMessage());
        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "Verification error: " + e.getMessage());
        }
    }

    private static boolean allScalarsInFr(PublicInputs values) {
        for (BigInteger value : values.values()) {
            if (value == null || value.signum() < 0 || value.compareTo(BLS12_381_R) >= 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * Decode and validate a snarkjs G1 point [x, y, z] (projective, decimal strings).
     */
    private P1_Affine decodeG1(String label, List<BigInteger> coords) {
        var point = new P1_Affine(decodeG1Bytes(label, coords));
        requireValidNonInfinity(label, point);
        return point;
    }

    private static byte[] decodeG1Bytes(String label, List<BigInteger> coords) {
        if (coords.size() != 3) {
            throw new IllegalArgumentException(label + " must have 3 projective coordinates");
        }
        var x = coords.get(0);
        var y = coords.get(1);
        var z = coords.get(2);
        requireFp(label + ".x", x);
        requireFp(label + ".y", y);
        requireFp(label + ".z", z);

        // Convert from projective to affine
        if (z.equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException(label + " must not be point at infinity");
        }

        BigInteger xAffine, yAffine;
        if (z.equals(BigInteger.ONE)) {
            xAffine = x;
            yAffine = y;
        } else {
            var zInv = z.modInverse(BLS12_381_P);
            xAffine = x.multiply(zInv).mod(BLS12_381_P);
            yAffine = y.multiply(zInv).mod(BLS12_381_P);
        }

        // Serialize as uncompressed: 96 bytes = x (48 bytes) + y (48 bytes), big-endian
        var result = new byte[FP_SIZE * 2];
        writeFp(result, 0, xAffine);
        writeFp(result, FP_SIZE, yAffine);
        return result;
    }

    /**
     * Decode a snarkjs G2 point [[x_c0,x_c1],[y_c0,y_c1],[z_c0,z_c1]] to blst uncompressed bytes.
     */
    private P2_Affine decodeG2(String label, List<List<BigInteger>> coords) {
        var point = new P2_Affine(decodeG2Bytes(label, coords));
        requireValidNonInfinity(label, point);
        return point;
    }

    private static byte[] decodeG2Bytes(String label, List<List<BigInteger>> coords) {
        if (coords.size() != 3) {
            throw new IllegalArgumentException(label + " must have 3 projective coordinates");
        }
        requireFp2(label + ".x", coords.get(0));
        requireFp2(label + ".y", coords.get(1));
        requireFp2(label + ".z", coords.get(2));

        var xc0 = coords.get(0).get(0);
        var xc1 = coords.get(0).get(1);
        var yc0 = coords.get(1).get(0);
        var yc1 = coords.get(1).get(1);
        var zc0 = coords.get(2).get(0);
        var zc1 = coords.get(2).get(1);

        boolean zIsOne = zc0.equals(BigInteger.ONE) && zc1.equals(BigInteger.ZERO);
        boolean zIsZero = zc0.equals(BigInteger.ZERO) && zc1.equals(BigInteger.ZERO);

        if (zIsZero) {
            throw new IllegalArgumentException(label + " must not be point at infinity");
        }

        BigInteger xc0Affine, xc1Affine, yc0Affine, yc1Affine;
        if (zIsOne) {
            xc0Affine = xc0;
            xc1Affine = xc1;
            yc0Affine = yc0;
            yc1Affine = yc1;
        } else {
            // Fp2 inversion needed — complex, but snarkjs always outputs z=[1,0]
            throw new UnsupportedOperationException("Non-trivial z coordinate in G2 not supported");
        }

        // blst G2 serialization: 192 bytes = x_c1 (48) + x_c0 (48) + y_c1 (48) + y_c0 (48)
        // Note: blst uses c1 first (imaginary), then c0 (real) for Fp2
        var result = new byte[FP_SIZE * 4];
        writeFp(result, 0, xc1Affine);
        writeFp(result, FP_SIZE, xc0Affine);
        writeFp(result, FP_SIZE * 2, yc1Affine);
        writeFp(result, FP_SIZE * 3, yc0Affine);
        return result;
    }

    private static void requireValidNonInfinity(String label, P1_Affine point) {
        if (point.is_inf()) {
            throw new IllegalArgumentException(label + " must not be point at infinity");
        }
        if (!point.on_curve() || !point.in_group()) {
            throw new IllegalArgumentException(label + " must be on curve and in subgroup");
        }
    }

    private static void requireValidNonInfinity(String label, P2_Affine point) {
        if (point.is_inf()) {
            throw new IllegalArgumentException(label + " must not be point at infinity");
        }
        if (!point.on_curve() || !point.in_group()) {
            throw new IllegalArgumentException(label + " must be on curve and in subgroup");
        }
    }

    private static void requireFp2(String label, List<BigInteger> values) {
        if (values.size() != 2) {
            throw new IllegalArgumentException(label + " must have 2 Fp coordinates");
        }
        requireFp(label + ".c0", values.get(0));
        requireFp(label + ".c1", values.get(1));
    }

    private static void requireFp(String label, BigInteger value) {
        if (value == null || value.signum() < 0 || value.compareTo(BLS12_381_P) >= 0) {
            throw new IllegalArgumentException(label + " must be in [0, p)");
        }
    }

    /**
     * Write a field element as 48-byte big-endian into buffer at offset.
     */
    private static void writeFp(byte[] buf, int offset, BigInteger value) {
        var bytes = value.toByteArray();
        // BigInteger.toByteArray() may have a leading zero byte for positive numbers
        int srcStart = (bytes.length > FP_SIZE) ? bytes.length - FP_SIZE : 0;
        int destStart = offset + FP_SIZE - Math.min(bytes.length, FP_SIZE);
        System.arraycopy(bytes, srcStart, buf, destStart, Math.min(bytes.length, FP_SIZE));
    }
}
