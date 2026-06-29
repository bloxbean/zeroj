package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Test-only validator for the fixed four-public-input Groth16 path.
 */
@SpendingValidator
public class Groth16BLS12381FixedFourInputVerifier {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, PlutusData ctx) {
        PlutusData inputs0 = Builtins.unListData(datum);
        if (Builtins.nullList(inputs0)) return false;

        PlutusData inputs1 = Builtins.tailList(inputs0);
        if (Builtins.nullList(inputs1)) return false;

        PlutusData inputs2 = Builtins.tailList(inputs1);
        if (Builtins.nullList(inputs2)) return false;

        PlutusData inputs3 = Builtins.tailList(inputs2);
        if (Builtins.nullList(inputs3)) return false;

        if (!Builtins.nullList(Builtins.tailList(inputs3))) return false;

        BigInteger pub0 = Builtins.asInteger(Builtins.headList(inputs0));
        BigInteger pub1 = Builtins.asInteger(Builtins.headList(inputs1));
        BigInteger pub2 = Builtins.asInteger(Builtins.headList(inputs2));
        BigInteger pub3 = Builtins.asInteger(Builtins.headList(inputs3));

        return Groth16BLS12381Lib.verifyFour(pub0, pub1, pub2, pub3,
                proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }
}
