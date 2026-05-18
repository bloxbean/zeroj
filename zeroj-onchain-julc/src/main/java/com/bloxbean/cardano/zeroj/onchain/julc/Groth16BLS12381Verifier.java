package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.BlsLib;

import java.math.BigInteger;

/**
 * Fixed two-public-input Groth16 BLS12-381 verifier as a Plutus V3 spending
 * validator.
 * <p>
 * Verification key points are baked in at deploy time via {@link Param}.
 * The proof (piA, piB, piC) is passed as the redeemer (compressed BLS bytes).
 * Public inputs are passed in the datum as a list of integers.
 * <p>
 * Verification equation:
 * <pre>
 *   finalVerify(
 *     mulMlResult(millerLoop(A, B), millerLoop(-alpha, beta)),
 *     mulMlResult(millerLoop(vk_x, gamma), millerLoop(C, delta))
 *   )
 * </pre>
 *
 * @deprecated Use {@link Groth16BLS12381GenericVerifier}. This class is kept
 * only for compatibility with older examples that baked exactly two public
 * inputs as three separate IC parameters.
 */
@SpendingValidator
@Deprecated
public class Groth16BLS12381Verifier {

    // VK points — compressed bytes baked at compile time
    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static byte[] vkIc0;     // G1 compressed 48 bytes
    @Param static byte[] vkIc1;     // G1 compressed 48 bytes
    @Param static byte[] vkIc2;     // G1 compressed 48 bytes

    /**
     * Groth16 proof points (compressed BLS bytes), passed as redeemer.
     */
    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        // 1. Uncompress proof points
        byte[] a = BlsLib.g1Uncompress(proof.piA());
        byte[] b = BlsLib.g2Uncompress(proof.piB());
        byte[] c = BlsLib.g1Uncompress(proof.piC());

        // 2. Uncompress VK points
        byte[] alpha = BlsLib.g1Uncompress(vkAlpha);
        byte[] beta  = BlsLib.g2Uncompress(vkBeta);
        byte[] gamma = BlsLib.g2Uncompress(vkGamma);
        byte[] delta = BlsLib.g2Uncompress(vkDelta);
        byte[] ic0   = BlsLib.g1Uncompress(vkIc0);
        byte[] ic1   = BlsLib.g1Uncompress(vkIc1);
        byte[] ic2   = BlsLib.g1Uncompress(vkIc2);

        // 3. Extract public inputs from datum (list of integers)
        PlutusData inputs = Builtins.unListData(datum);
        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs));
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(Builtins.tailList(inputs)));

        // 4. Compute vk_x = IC[0] + pub[0]*IC[1] + pub[1]*IC[2]
        byte[] s0 = BlsLib.g1ScalarMul(pub0, ic1);
        byte[] s1 = BlsLib.g1ScalarMul(pub1, ic2);
        byte[] vkX = BlsLib.g1Add(ic0, BlsLib.g1Add(s0, s1));

        // 5. Groth16 pairing check
        byte[] negAlpha = BlsLib.g1Neg(alpha);
        byte[] lhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(a, b),
                BlsLib.millerLoop(negAlpha, beta));
        byte[] rhs = BlsLib.mulMlResult(
                BlsLib.millerLoop(vkX, gamma),
                BlsLib.millerLoop(c, delta));

        return BlsLib.finalVerify(lhs, rhs);
    }
}
