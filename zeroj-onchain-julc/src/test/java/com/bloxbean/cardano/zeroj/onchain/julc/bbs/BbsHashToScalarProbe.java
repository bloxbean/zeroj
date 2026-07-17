package com.bloxbean.cardano.zeroj.onchain.julc.bbs;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib.BbsHashToScalar;

import java.math.BigInteger;

/**
 * Test harness only: a trivial spending validator that exposes {@link BbsHashToScalar#hashToScalar}
 * to the Julc VM so it can be differential-tested against the off-chain
 * {@code CfrgBbsCore.hashToScalar}. The redeemer carries a {@code (message, dst, expected)} triple;
 * the validator recomputes the scalar on-chain and asserts it equals {@code expected}.
 */
@SpendingValidator
public class BbsHashToScalarProbe {

    record Probe(byte[] message, byte[] dst, BigInteger expected) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Probe probe, ScriptContext ctx) {
        return BbsHashToScalar.hashToScalar(probe.message(), probe.dst()).equals(probe.expected());
    }
}
