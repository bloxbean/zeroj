package org.zeroj.onchain.julc.groth16.validator;

import org.julclang.core.PlutusData;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Test-only probe of {@code verifyFour} in the optimized library (issue #84 differential test). The datum
 * holds exactly four public inputs; the redeemer carries the expected result (see
 * {@link Groth16VerifyOutcomeProbe}).
 */
@SpendingValidator
public class Groth16VerifyFourOutcomeProbe {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Probe(byte[] piA, byte[] piB, byte[] piC, BigInteger expect) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, PlutusData ctx) {
        PlutusData inputs0 = Builtins.unListData(datum);
        PlutusData inputs1 = Builtins.tailList(inputs0);
        PlutusData inputs2 = Builtins.tailList(inputs1);
        PlutusData inputs3 = Builtins.tailList(inputs2);
        boolean ok = Groth16BLS12381Lib.verifyFour(Builtins.asInteger(Builtins.headList(inputs0)),
                Builtins.asInteger(Builtins.headList(inputs1)), Builtins.asInteger(Builtins.headList(inputs2)),
                Builtins.asInteger(Builtins.headList(inputs3)),
                probe.piA(), probe.piB(), probe.piC(), vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
        return probe.expect().equals(BigInteger.ONE) ? ok : !ok;
    }
}
