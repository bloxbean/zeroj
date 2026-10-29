package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/** Test harness only: {@link PedersenG1Lib#hashBytesToScalar} must equal the expected scalar. */
@SpendingValidator
public class PedersenG1HashProbe {

    record Probe(byte[] payload, BigInteger expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return PedersenG1Lib.hashBytesToScalar(probe.payload()).equals(probe.expected());
    }
}
