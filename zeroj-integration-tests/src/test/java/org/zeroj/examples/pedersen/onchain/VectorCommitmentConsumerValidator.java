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
import org.julclang.stdlib.lib.ContextsLib;
import org.julclang.stdlib.lib.ValuesLib;
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * ADR-0051 M4 reference consumer of a {@code pedersen-jubjub-vector-v1} commitment
 * ({@code docs/specs/pedersen-jubjub-vector-v1.md} §5–§6).
 *
 * <p>A UTxO locked here is a <b>claim</b>: datum {@code Claim(beneficiary, u, v)} names one
 * commitment and who may redeem it. The redeemer carries only the Groth16 proof. Every public
 * input comes from the ledger or the script: {@code [σ, u, v]}, with {@code σ} the script
 * parameter (the verifier's registry entry, alongside the verification key) and {@code (u, v)}
 * from the consumed claim's datum.
 *
 * <p>What this validator binds:
 * <ul>
 *   <li><b>Statement:</b> only a proof for the expected schema digest and this claim's commitment
 *       verifies.</li>
 *   <li><b>Provenance:</b> statement binding is not provenance — anyone who knows an opening can
 *       prove the same point under another schema of the same shape. The transaction must carry,
 *       as a reference input, the commitment's issuance record: the issuer-minted token whose
 *       <b>name</b> is {@code blake2b_256(I2OSP32(u) ‖ I2OSP32(v) ‖ I2OSP32(σ))}, at an output whose
 *       inline datum is {@code IssuanceRecord(u, v, σ)}. Because the token name commits to the
 *       record, holding one record's token cannot vouch for another commitment or schema. No such
 *       record, no spend (fail closed).</li>
 *   <li><b>Authorization and replay:</b> the claim's beneficiary must sign; a claim is an unspent
 *       output and is redeemed once; exactly one input may come from this script address, so one
 *       presentation cannot satisfy several claims.</li>
 *   <li><b>Canonical inputs:</b> {@code σ}, {@code u} and {@code v} must be field elements.</li>
 * </ul>
 * The issuing policy is assumed to mint a record token only after its own checks (in the E2E
 * test, a native script requiring the issuer's signature).
 */
@SpendingValidator
public class VectorCommitmentConsumerValidator {

    @Param static byte[] expectedSchemaDigest;   // 32-byte big-endian σ
    @Param static byte[] issuancePolicyId;
    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Claim(byte[] beneficiary, BigInteger u, BigInteger v) {}

    record Presentation(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(Claim claim, Presentation presentation, ScriptContext ctx) {
        BigInteger sigma = Builtins.byteStringToInteger(true, expectedSchemaDigest);
        if (Builtins.lengthOfByteString(expectedSchemaDigest) != 32
                || Builtins.lengthOfByteString(issuancePolicyId) != 28
                || Builtins.lengthOfByteString(claim.beneficiary()) != 28
                || !canonicalField(sigma)
                || !canonicalField(claim.u())
                || !canonicalField(claim.v())
                || !signedBy(ctx, claim.beneficiary())) {
            return false;
        }

        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        int scriptInputs = 0;
        for (TxInInfo input : ctx.txInfo().inputs()) {
            if (Builtins.equalsData(input.resolved().address(), ownInput.resolved().address())) {
                scriptInputs = scriptInputs + 1;
            } else {
                scriptInputs = scriptInputs;
            }
        }
        if (scriptInputs != 1) return false;

        byte[] recordToken = recordTokenName(claim.u(), claim.v(), sigma);
        PlutusData expectedRecord = Builtins.constrData(0,
                Builtins.mkCons(Builtins.iData(claim.u()),
                Builtins.mkCons(Builtins.iData(claim.v()),
                Builtins.mkCons(Builtins.iData(sigma),
                        Builtins.mkNilData()))));
        boolean recorded = false;
        for (TxInInfo reference : ctx.txInfo().referenceInputs()) {
            TxOut record = reference.resolved();
            boolean matches = ValuesLib.assetOf(record.value(), issuancePolicyId, recordToken)
                    .compareTo(BigInteger.ZERO) > 0
                    && Builtins.equalsData(inlineDatum(record), expectedRecord);
            recorded = recorded || matches;
        }
        if (!recorded) return false;

        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(sigma),
                Builtins.mkCons(Builtins.iData(claim.u()),
                Builtins.mkCons(Builtins.iData(claim.v()),
                        Builtins.mkNilData()))));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                presentation.piA(), presentation.piB(), presentation.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    /** {@code blake2b_256(I2OSP32(u) ‖ I2OSP32(v) ‖ I2OSP32(σ))}. */
    private static byte[] recordTokenName(BigInteger u, BigInteger v, BigInteger sigma) {
        return Builtins.blake2b_256(Builtins.appendByteString(
                Builtins.integerToByteString(true, 32, u),
                Builtins.appendByteString(
                        Builtins.integerToByteString(true, 32, v),
                        Builtins.integerToByteString(true, 32, sigma))));
    }

    private static boolean signedBy(ScriptContext ctx, byte[] beneficiary) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), beneficiary);
        }
        return found;
    }

    /** The inline datum; a missing or hashed datum yields an integer, which never matches. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
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
