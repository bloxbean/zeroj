package org.zeroj.examples.bbs.onchain;

import org.julclang.ledger.ScriptContext;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.zeroj.onchain.julc.bbs.lib.BbsProofVerify;

import java.math.BigInteger;

/**
 * ADR-0064 example spending validator (test fixture, not published): locks an output behind a
 * 5-message BBS credential disclosing attributes {@code {2, 3}} plus owner signature and expected
 * disclosed attribute / presentation-header policy.
 *
 * <p>Example only — demonstrates how an application validator composes {@link BbsProofVerify#verify}
 * with {@link ScriptContext} authorization and expected claim checks for Yaci DevKit verification.</p>
 */
@SpendingValidator
public class BbsClaimExampleValidator {

    @Param static byte[] w;
    @Param static byte[] bp2;
    @Param static byte[] p1;
    @Param static byte[] q1;
    @Param static byte[] h0;
    @Param static byte[] h1;
    @Param static byte[] h2;
    @Param static byte[] h3;
    @Param static byte[] h4;
    @Param static byte[] domainBytes;
    @Param static byte[] dstH2S;
    @Param static byte[] dstMap;

    public record ClaimPolicy(byte[] owner, byte[] expectedMsg2, byte[] expectedMsg3, byte[] expectedPh) {}

    public record ClaimProof(byte[] abar, byte[] bbar, byte[] d,
                             BigInteger eHat, BigInteger r1Hat, BigInteger r3Hat,
                             BigInteger mHat0, BigInteger mHat1, BigInteger mHat2, BigInteger c,
                             byte[] msg2, byte[] msg3, byte[] ph) {}

    @Entrypoint
    public static boolean validate(ClaimPolicy datum, ClaimProof proof, ScriptContext ctx) {
        if (Builtins.lengthOfByteString(datum.owner()) != 28L || !signedBy(ctx, datum.owner())) {
            return false;
        }
        if (!Builtins.equalsByteString(proof.msg2(), datum.expectedMsg2())
                || !Builtins.equalsByteString(proof.msg3(), datum.expectedMsg3())
                || !Builtins.equalsByteString(proof.ph(), datum.expectedPh())) {
            return false;
        }
        return BbsProofVerify.verify(
                w, bp2, p1, q1, h0, h1, h2, h3, h4,
                Builtins.byteStringToInteger(true, domainBytes), dstH2S, dstMap,
                proof.abar(), proof.bbar(), proof.d(),
                proof.eHat(), proof.r1Hat(), proof.r3Hat(),
                proof.mHat0(), proof.mHat1(), proof.mHat2(), proof.c(),
                proof.msg2(), proof.msg3(), proof.ph());
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
    }
}
