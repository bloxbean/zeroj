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

            // Parse points from snarkjs JSON to blst format
            var piA = decodeG1(proof.piA());
            var piB = decodeG2(proof.piB());
            var piC = decodeG1(proof.piC());

            var alpha = decodeG1(vk.vkAlpha1());
            var beta = decodeG2(vk.vkBeta2());
            var gamma = decodeG2(vk.vkGamma2());
            var delta = decodeG2(vk.vkDelta2());

            // Compute vk_x = IC[0] + sum(pub_i * IC[i+1])
            P1 vkX = new P1(decodeG1Bytes(vk.ic().get(0)));
            for (int i = 0; i < publicInputs.size(); i++) {
                var icPoint = new P1(decodeG1Bytes(vk.ic().get(i + 1)));
                icPoint.mult(publicInputs.get(i));
                vkX.add(new P1_Affine(icPoint.serialize()));
            }

            // Negate A for the pairing check: e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
            // => e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) should be... no.
            // Standard check: e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == 1

            // Negate the points that need negation
            var negAlpha = new P1(alpha);
            negAlpha.neg();

            var negVkX = new P1(vkX.compress());
            negVkX.neg();

            var negC = new P1(piC);
            negC.neg();

            // Compute multi-pairing
            var pairingAB = new PT(new P1_Affine(new P1(piA).serialize()), new P2_Affine(new P2(piB).serialize()));
            var pairingAlphaBeta = new PT(new P1_Affine(negAlpha.serialize()), new P2_Affine(new P2(beta).serialize()));
            var pairingVkxGamma = new PT(new P1_Affine(negVkX.serialize()), new P2_Affine(new P2(gamma).serialize()));
            var pairingCDelta = new PT(new P1_Affine(negC.serialize()), new P2_Affine(new P2(delta).serialize()));

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
        } catch (Exception e) {
            return VerificationResult.error(
                    VerificationResult.ReasonCode.INTERNAL_ERROR,
                    "Verification error: " + e.getMessage());
        }
    }

    /**
     * Decode a snarkjs G1 point [x, y, z] (projective, decimal strings) to blst uncompressed bytes.
     * Returns uncompressed serialized bytes for blst P1 constructor.
     */
    private byte[] decodeG1(List<BigInteger> coords) {
        return decodeG1Bytes(coords);
    }

    private static byte[] decodeG1Bytes(List<BigInteger> coords) {
        var x = coords.get(0);
        var y = coords.get(1);
        var z = coords.get(2);

        // Convert from projective to affine
        if (z.equals(BigInteger.ZERO)) {
            // Point at infinity — return identity serialization
            return new byte[FP_SIZE]; // Compressed identity
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
    private byte[] decodeG2(List<List<BigInteger>> coords) {
        var xc0 = coords.get(0).get(0);
        var xc1 = coords.get(0).get(1);
        var yc0 = coords.get(1).get(0);
        var yc1 = coords.get(1).get(1);
        var zc0 = coords.get(2).get(0);
        var zc1 = coords.get(2).get(1);

        boolean zIsOne = zc0.equals(BigInteger.ONE) && zc1.equals(BigInteger.ZERO);
        boolean zIsZero = zc0.equals(BigInteger.ZERO) && zc1.equals(BigInteger.ZERO);

        if (zIsZero) {
            return new byte[FP_SIZE * 2]; // Compressed identity
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
