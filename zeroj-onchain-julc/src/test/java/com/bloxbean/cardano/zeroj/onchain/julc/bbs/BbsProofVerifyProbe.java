package com.bloxbean.cardano.zeroj.onchain.julc.bbs;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.bbs.lib.BbsProofVerify;

import java.math.BigInteger;

/**
 * Test harness: exposes {@link BbsProofVerify#verify} to the Julc VM so it can be differential-tested
 * against a real off-chain BBS presentation. Params are the verification-key material (baked at
 * deploy); the redeemer is one claim's proof + disclosed messages + presentation header. The
 * validator returns whether the BBS proof verifies.
 */
@SpendingValidator
public class BbsProofVerifyProbe {

    @Param static byte[] w;
    @Param static byte[] bp2;
    @Param static byte[] p1;
    @Param static byte[] q1;
    @Param static byte[] h0;
    @Param static byte[] h1;
    @Param static byte[] h2;
    @Param static byte[] h3;
    @Param static byte[] h4;
    @Param static byte[] domainBytes;   // 32-byte big-endian domain scalar
    @Param static byte[] dstH2S;
    @Param static byte[] dstMap;

    record Claim(byte[] abar, byte[] bbar, byte[] d,
                 BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
                 BigInteger mHat0, BigInteger mHat1, BigInteger mHat2, BigInteger c,
                 byte[] msg2, byte[] msg3, byte[] ph) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Claim p, ScriptContext ctx) {
        return BbsProofVerify.verify(
                w, bp2, p1, q1, h0, h1, h2, h3, h4,
                Builtins.byteStringToInteger(true, domainBytes), dstH2S, dstMap,
                p.abar(), p.bbar(), p.d(),
                p.eHat(), p.r1Hat(), p.r3Hat(), p.mHat0(), p.mHat1(), p.mHat2(), p.c(),
                p.msg2(), p.msg3(), p.ph());
    }
}
