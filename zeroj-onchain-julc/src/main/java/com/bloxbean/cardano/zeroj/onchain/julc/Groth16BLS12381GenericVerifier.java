package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;

import java.math.BigInteger;

/**
 * Generic on-chain Groth16 BLS12-381 verifier as a Plutus V3 spending validator.
 * <p>
 * Verification key points are baked in at deploy time. Unlike
 * {@link Groth16BLS12381Verifier}, this verifier accepts the full IC vector as
 * a Plutus list parameter, so it supports any public-input count.
 * <p>
 * Datum: list of public input integers in verification-key schema order.
 * Redeemer: compressed Groth16 proof points.
 * Parameter {@code vkIc}: list of compressed G1 IC points, where
 * {@code len(vkIc) == len(publicInputs) + 1}.
 */
@SpendingValidator
public class Groth16BLS12381GenericVerifier {

    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed 48-byte IC points

    /**
     * Groth16 proof points (compressed BLS bytes), passed as redeemer.
     */
    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        PlutusData inputsCursor = Builtins.unListData(datum);
        PlutusData icCursor = Builtins.unListData(vkIc);

        if (Builtins.nullList(icCursor)) {
            return false;
        }

        byte[] vkX = BlsLib.g1Uncompress(Builtins.unBData(Builtins.headList(icCursor)));
        return verifyWithPublicInputs(inputsCursor, Builtins.tailList(icCursor), vkX, proof);
    }

    private static boolean verifyWithPublicInputs(PlutusData inputsCursor,
                                                  PlutusData icCursor,
                                                  byte[] vkX,
                                                  Groth16Proof proof) {
        if (!matchingLengths(inputsCursor, icCursor)) {
            return false;
        }

        byte[] computedVkX = computeVkX(inputsCursor, icCursor, vkX);

        byte[] a = BlsLib.g1Uncompress(proof.piA());
        byte[] b = BlsLib.g2Uncompress(proof.piB());
        byte[] c = BlsLib.g1Uncompress(proof.piC());

        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);

        byte[] negAlpha = BlsLib.g1Neg(alpha);
        byte[] lhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(a, b),
                BlsLib.millerLoop(negAlpha, beta));
        byte[] rhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(computedVkX, gamma),
                BlsLib.millerLoop(c, delta));

        return BlsLib.finalVerify(lhs, rhs);
    }

    private static boolean matchingLengths(PlutusData inputsCursor, PlutusData icCursor) {
        if (Builtins.nullList(inputsCursor)) {
            return Builtins.nullList(icCursor);
        } else if (Builtins.nullList(icCursor)) {
            return false;
        } else {
            return matchingLengths(Builtins.tailList(inputsCursor), Builtins.tailList(icCursor));
        }
    }

    private static byte[] computeVkX(PlutusData inputsCursor, PlutusData icCursor, byte[] vkX) {
        if (Builtins.nullList(inputsCursor)) {
            return vkX;
        } else {
            BigInteger publicInput = Builtins.asInteger(Builtins.headList(inputsCursor));
            byte[] ic = BlsLib.g1Uncompress(Builtins.unBData(Builtins.headList(icCursor)));
            byte[] scaled = BlsLib.g1ScalarMul(publicInput, ic);
            byte[] nextVkX = BlsLib.g1Add(vkX, scaled);
            return computeVkX(Builtins.tailList(inputsCursor), Builtins.tailList(icCursor), nextVkX);
        }
    }
}
