package org.zeroj.onchain.julc.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * Test harness only: a scalar opening through {@link PedersenG1Lib}: the unbounded check, or, with
 * {@code bounded}, check 2 with width {@code amountBits} (any integer, including invalid widths).
 */
@SpendingValidator
public class PedersenG1OpeningProbe {

    record Probe(byte[] commitment, BigInteger value, BigInteger blinding, boolean bounded, BigInteger amountBits) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        if (!probe.bounded()) {
            return PedersenG1Lib.verifyScalarOpening(
                    PedersenG1Lib.decodeCommitment(probe.commitment()), probe.value(), probe.blinding());
        }
        return PedersenG1Lib.verifyScalarOpeningBounded(
                PedersenG1Lib.decodeCommitment(probe.commitment()), probe.value(), probe.blinding(), probe.amountBits());
    }
}
