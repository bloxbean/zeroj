package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/** Test harness only: a byte opening through {@link PedersenG1Lib#verifyBytesOpening}. */
@SpendingValidator
public class PedersenG1BytesProbe {

    record Probe(byte[] commitment, byte[] payload, BigInteger blinding) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return PedersenG1Lib.verifyBytesOpening(
                PedersenG1Lib.decodeCommitment(probe.commitment()), probe.payload(), probe.blinding());
    }
}
