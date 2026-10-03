package org.zeroj.examples.pedersen.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.Param;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * ADR-0051 M4 reference consumer of a {@code pedersen-jubjub-vector-v1} commitment
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md} §5–§6).
 *
 * <p>The applied script is the verifier's registry entry: it fixes one verification key and one
 * expected schema digest. The proof's public inputs are {@code [σ, u, v]}, and {@code σ} is taken
 * from the parameter, never from the redeemer — so only a proof for the expected schema verifies.
 *
 * <p>Statement binding is not provenance. Anyone who knows an opening can prove the same point
 * under another schema of the same shape. The transaction must therefore carry, as a reference
 * input, the commitment's <b>issuance record</b>: an output holding the issuance token (minted
 * only by the issuing policy) whose inline datum is {@code IssuanceRecord(u, v, σ)} for exactly
 * the presented commitment and the expected schema. No matching record, no spend (fail closed).
 */
@SpendingValidator
public class VectorCommitmentConsumerValidator {

    @Param static byte[] expectedSchemaDigest;   // 32-byte big-endian σ
    @Param static byte[] issuancePolicyId;
    @Param static byte[] issuanceTokenName;
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Presentation(BigInteger u, BigInteger v, byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(PlutusData datum, Presentation presentation, ScriptContext ctx) {
        BigInteger sigma = Builtins.byteStringToInteger(true, expectedSchemaDigest);
        if (Builtins.lengthOfByteString(expectedSchemaDigest) != 32
                || Builtins.lengthOfByteString(issuancePolicyId) != 28
                || !canonicalField(sigma)
                || !canonicalField(presentation.u())
                || !canonicalField(presentation.v())) {
            return false;
        }

        boolean recorded = false;
        for (TxInInfo reference : ctx.txInfo().referenceInputs()) {
            TxOut record = reference.resolved();
            boolean matches = ValuesLib.assetOf(record.value(), issuancePolicyId, issuanceTokenName)
                    .compareTo(BigInteger.ZERO) > 0
                    && isRecord(inlineDatum(record), presentation.u(), presentation.v(), sigma);
            recorded = recorded || matches;
        }
        if (!recorded) return false;

        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(sigma),
                Builtins.mkCons(Builtins.iData(presentation.u()),
                Builtins.mkCons(Builtins.iData(presentation.v()),
                        Builtins.mkNilData()))));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                presentation.piA(), presentation.piB(), presentation.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    /** The inline datum; a missing or hashed datum yields an integer, which never matches. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** {@code IssuanceRecord(u, v, σ)} = {@code Constr 0 [int, int, int]} with exactly these values. */
    private static boolean isRecord(PlutusData value, BigInteger u, BigInteger v, BigInteger sigma) {
        PlutusData expected = Builtins.constrData(0,
                Builtins.mkCons(Builtins.iData(u),
                Builtins.mkCons(Builtins.iData(v),
                Builtins.mkCons(Builtins.iData(sigma),
                        Builtins.mkNilData()))));
        return Builtins.equalsData(value, expected);
    }

    private static boolean canonicalField(BigInteger value) {
        return value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(fr()) < 0;
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
