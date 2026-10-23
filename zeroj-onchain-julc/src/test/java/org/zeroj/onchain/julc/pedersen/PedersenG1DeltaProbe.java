package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/** Test harness only: {@link PedersenG1Lib#applyPublicDelta} must give the expected encoding. */
@SpendingValidator
public class PedersenG1DeltaProbe {

    record Probe(byte[] commitment, BigInteger delta, BigInteger deltaBits, byte[] expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return Builtins.equalsByteString(PedersenG1Lib.encodeCommitment(PedersenG1Lib.applyPublicDelta(
                PedersenG1Lib.decodeCommitment(probe.commitment()), probe.delta(), probe.deltaBits())), probe.expected());
    }
}
