package org.zeroj.onchain.julc.groth16.validator;

import org.julclang.core.PlutusData;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381LibReference;

import java.math.BigInteger;

/**
 * Test-only probe of {@code verify} in the pre-#84 reference library (issue #84 differential test). The redeemer
 * carries the expected result: the script succeeds iff {@code verify} returns it, so running a
 * vector with {@code expect = 1} and {@code expect = 0} tells accept, {@code false} and a builtin
 * failure apart.
 */
@SpendingValidator
public class Groth16VerifyOutcomeProbeReference {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Probe(byte[] piA, byte[] piB, byte[] piC, BigInteger expect) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, PlutusData ctx) {
        boolean ok = Groth16BLS12381LibReference.verify(datum, probe.piA(), probe.piB(), probe.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
        return probe.expect().equals(BigInteger.ONE) ? ok : !ok;
    }
}
