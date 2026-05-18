package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;

/**
 * On-chain Groth16 BLS12-381 verifier as a Plutus V3 spending validator.
 * <p>
 * Verification key points are baked in at deploy time. The full IC vector is
 * passed as a Plutus list parameter, so this verifier supports any public-input
 * count for Groth16 circuits over BLS12-381.
 * <p>
 * Datum: list of public input integers in verification-key schema order.
 * Redeemer: compressed Groth16 proof points.
 * Parameter {@code vkIc}: list of compressed G1 IC points, where
 * {@code len(vkIc) == len(publicInputs) + 1}.
 */
@SpendingValidator
public class Groth16BLS12381Verifier {

    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed 48-byte IC points

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        return Groth16BLS12381.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
