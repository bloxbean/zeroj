package com.bloxbean.cardano.zeroj.onchain.julc;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;

import java.math.BigInteger;

/**
 * Test-only custom validator demonstrating composition with Groth16BLS12381.
 */
@SpendingValidator
public class Groth16BLS12381FirstInputBindingVerifier {

    @Param static BigInteger expectedFirstPublicInput;
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        PlutusData inputs = Builtins.unListData(datum);
        if (Builtins.nullList(inputs)) {
            return false;
        }

        BigInteger firstPublicInput = Builtins.asInteger(Builtins.headList(inputs));
        boolean domainRuleHolds = firstPublicInput.equals(expectedFirstPublicInput);
        boolean proofValid = Groth16BLS12381.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return domainRuleHolds && proofValid;
    }
}
