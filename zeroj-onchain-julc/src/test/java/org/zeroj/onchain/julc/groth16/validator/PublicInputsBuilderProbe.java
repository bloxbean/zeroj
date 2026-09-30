package org.zeroj.onchain.julc.groth16.validator;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Test-only validator: builds the public-input list with {@code publicInputsN} for the arity in
 * the redeemer and accepts only if it equals the datum. Under Julc pre16 the old overloaded
 * {@code publicInputs} ran its last (6-input) body for every call (ADR-0050).
 */
@SpendingValidator
public class PublicInputsBuilderProbe {

    @Entrypoint
    public static boolean validate(PlutusData expected, PlutusData redeemer, ScriptContext ctx) {
        return Builtins.equalsData(build(Builtins.unIData(redeemer)), expected);
    }

    static PlutusData build(BigInteger n) {
        BigInteger a = BigInteger.valueOf(10);
        BigInteger b = BigInteger.valueOf(11);
        BigInteger c = BigInteger.valueOf(12);
        BigInteger d = BigInteger.valueOf(13);
        BigInteger e = BigInteger.valueOf(14);
        BigInteger f = BigInteger.valueOf(15);
        if (n.equals(BigInteger.valueOf(1))) {
            return Groth16BLS12381Lib.publicInputs1(a);
        } else if (n.equals(BigInteger.valueOf(2))) {
            return Groth16BLS12381Lib.publicInputs2(a, b);
        } else if (n.equals(BigInteger.valueOf(3))) {
            return Groth16BLS12381Lib.publicInputs3(a, b, c);
        } else if (n.equals(BigInteger.valueOf(4))) {
            return Groth16BLS12381Lib.publicInputs4(a, b, c, d);
        } else if (n.equals(BigInteger.valueOf(5))) {
            return Groth16BLS12381Lib.publicInputs5(a, b, c, d, e);
        } else {
            return Groth16BLS12381Lib.publicInputs6(a, b, c, d, e, f);
        }
    }
}
