package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.ScriptInfo;
import com.bloxbean.cardano.julc.ledger.TxOutRef;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Groth16 BLS12-381 verifier that binds the proof statement to the UTxO being spent.
 *
 * <p>The first public input must be
 * {@code blake2b_256(spentTxId || spentOutputIndex32) mod Fr}. This is only an
 * example policy: production validators should bind the statement to the
 * application-specific signer, datum, value, output, nullifier, or authorization
 * fields they require.</p>
 */
@SpendingValidator
public class Groth16BLS12381TxOutRefBindingVerifier {

    @Param static byte[] vkAlpha;   // G1 compressed 48 bytes
    @Param static byte[] vkBeta;    // G2 compressed 96 bytes
    @Param static byte[] vkGamma;   // G2 compressed 96 bytes
    @Param static byte[] vkDelta;   // G2 compressed 96 bytes
    @Param static PlutusData vkIc;  // List of G1 compressed 48-byte IC points

    record Groth16Proof(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Groth16Proof proof, ScriptContext ctx) {
        PlutusData inputs = Builtins.unListData(datum);
        if (Builtins.nullList(inputs)) {
            return false;
        }

        BigInteger firstPublicInput = Builtins.asInteger(Builtins.headList(inputs));
        boolean statementBoundToSpend = firstPublicInput.equals(spendingReferenceScalar(ctx));
        boolean proofValid = Groth16BLS12381Lib.verify(datum, proof.piA(), proof.piB(), proof.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);

        return statementBoundToSpend && proofValid;
    }

    private static BigInteger spendingReferenceScalar(ScriptContext ctx) {
        ScriptInfo scriptInfo = ctx.scriptInfo();
        if (scriptInfo instanceof ScriptInfo.SpendingScript spendingScript) {
            return txOutRefScalar(spendingScript.txOutRef());
        } else {
            return BigInteger.valueOf(-1);
        }
    }

    private static BigInteger txOutRefScalar(TxOutRef txOutRef) {
        byte[] indexBytes = Builtins.integerToByteString(true, 32, txOutRef.index());
        byte[] preimage = Builtins.appendByteString(txOutRef.txId().hash(), indexBytes);
        return Builtins.byteStringToInteger(true, Builtins.blake2b_256(preimage)).mod(fr());
    }

    private static BigInteger fr() {
        BigInteger base = BigInteger.valueOf(1000000000000000000L);
        return BigInteger.valueOf(52435L).multiply(base)
                .add(BigInteger.valueOf(875175126190479447L)).multiply(base)
                .add(BigInteger.valueOf(740508185965837690L)).multiply(base)
                .add(BigInteger.valueOf(552500527637822603L)).multiply(base)
                .add(BigInteger.valueOf(658699938581184513L));
    }
}
