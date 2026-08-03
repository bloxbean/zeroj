package com.bloxbean.cardano.zeroj.onchain.julc.groth16.validator;

import com.bloxbean.cardano.julc.core.PlutusData;
import com.bloxbean.cardano.julc.ledger.OutputDatum;
import com.bloxbean.cardano.julc.ledger.ScriptContext;
import com.bloxbean.cardano.julc.ledger.TxInInfo;
import com.bloxbean.cardano.julc.ledger.TxOut;
import com.bloxbean.cardano.julc.stdlib.Builtins;
import com.bloxbean.cardano.julc.stdlib.annotation.Entrypoint;
import com.bloxbean.cardano.julc.stdlib.annotation.Param;
import com.bloxbean.cardano.julc.stdlib.annotation.SpendingValidator;
import com.bloxbean.cardano.julc.stdlib.lib.ContextsLib;
import com.bloxbean.cardano.julc.stdlib.lib.ValuesLib;
import com.bloxbean.cardano.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * Representative application-bound validator for two-public-input authenticated-state
 * transition circuits.
 *
 * <p>One applied script is created per operation-specific verification key and release ID. The
 * state-token asset, authorized signer, release identity, and VK are all immutable script
 * parameters. The validator derives {@code [oldRoot,newRoot]} from the consumed datum and the
 * continuing output policy; callers never supply the old root as a free public input.</p>
 *
 * <p>Datum: {@code StateDatum(root, version)}. Redeemer:
 * {@code StateTransition(newRoot, releaseId, piA, piB, piC)}. The continuing output must preserve
 * the complete address and value, contain the unique state token, and carry inline datum
 * {@code StateDatum(newRoot, version + 1)}.</p>
 */
@SpendingValidator
public class Groth16AuthenticatedStateTransitionValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static byte[] statePolicyId;
    @Param static byte[] stateTokenName;
    @Param static byte[] authorizedSigner;
    @Param static byte[] releaseId;

    record StateDatum(BigInteger root, BigInteger version) {}

    record StateTransition(
            BigInteger newRoot,
            byte[] releaseId,
            byte[] piA,
            byte[] piB,
            byte[] piC) {}

    @Entrypoint
    public static boolean validate(
            StateDatum datum, StateTransition transition, ScriptContext ctx) {
        if (!validParameters()
                || !canonicalField(datum.root())
                || !canonicalField(transition.newRoot())
                || datum.version().compareTo(BigInteger.ZERO) < 0
                || datum.root().equals(transition.newRoot())
                || !Builtins.equalsByteString(releaseId, transition.releaseId())
                || !signedByAuthorizedOperator(ctx)) {
            return false;
        }

        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        if (!hasStateToken(ownInput.resolved())
                || !hasInlineStateDatum(
                        ownInput.resolved(), datum.root(), datum.version())) {
            return false;
        }

        int continuingCount = 0;
        TxOut continuingOutput = ownInput.resolved();
        for (TxOut output : ctx.txInfo().outputs()) {
            if (Builtins.equalsData(output.address(), ownInput.resolved().address())) {
                continuingCount = continuingCount + 1;
                continuingOutput = output;
            } else {
                continuingCount = continuingCount;
            }
        }
        if (continuingCount != 1
                || !hasStateToken(continuingOutput)
                || !Builtins.equalsData(
                        continuingOutput.value(), ownInput.resolved().value())
                || !hasInlineStateDatum(
                        continuingOutput,
                        transition.newRoot(),
                        datum.version().add(BigInteger.ONE))) {
            return false;
        }

        BigInteger inputStateTokens = BigInteger.ZERO;
        for (TxInInfo input : ctx.txInfo().inputs()) {
            inputStateTokens = inputStateTokens.add(
                    ValuesLib.assetOf(input.resolved().value(), statePolicyId, stateTokenName));
        }
        BigInteger outputStateTokens = BigInteger.ZERO;
        for (TxOut output : ctx.txInfo().outputs()) {
            outputStateTokens = outputStateTokens.add(
                    ValuesLib.assetOf(output.value(), statePolicyId, stateTokenName));
        }
        if (!inputStateTokens.equals(BigInteger.ONE)
                || !outputStateTokens.equals(BigInteger.ONE)
                || !ValuesLib.assetOf(
                        ctx.txInfo().mint(), statePolicyId, stateTokenName).equals(BigInteger.ZERO)) {
            return false;
        }

        PlutusData publicInputs = Builtins.listData(Builtins.mkCons(
                Builtins.iData(datum.root()),
                Builtins.mkCons(
                        Builtins.iData(transition.newRoot()), Builtins.mkNilData())));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                transition.piA(), transition.piB(), transition.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    private static boolean validParameters() {
        return Builtins.lengthOfByteString(statePolicyId) == 28
                && Builtins.lengthOfByteString(stateTokenName) <= 32
                && Builtins.lengthOfByteString(authorizedSigner) == 28
                && Builtins.lengthOfByteString(releaseId) == 32;
    }

    private static boolean canonicalField(BigInteger value) {
        return value.compareTo(BigInteger.ZERO) >= 0 && value.compareTo(fr()) < 0;
    }

    private static boolean signedByAuthorizedOperator(ScriptContext ctx) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), authorizedSigner);
        }
        return found;
    }

    private static boolean hasStateToken(TxOut output) {
        return ValuesLib.assetOf(
                output.value(), statePolicyId, stateTokenName).equals(BigInteger.ONE);
    }

    private static boolean hasInlineStateDatum(
            TxOut output, BigInteger expectedRoot, BigInteger expectedVersion) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline ->
                    isStateDatum(inline.datum(), expectedRoot, expectedVersion);
            case OutputDatum.OutputDatumHash ignored -> false;
            case OutputDatum.NoOutputDatum ignored -> false;
        };
    }

    private static boolean isStateDatum(
            PlutusData value, BigInteger expectedRoot, BigInteger expectedVersion) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData fields = Builtins.constrFields(value);
        if (Builtins.nullList(fields)) return false;
        BigInteger root = Builtins.asInteger(Builtins.headList(fields));
        PlutusData afterRoot = Builtins.tailList(fields);
        if (Builtins.nullList(afterRoot)) return false;
        BigInteger version = Builtins.asInteger(Builtins.headList(afterRoot));
        return Builtins.nullList(Builtins.tailList(afterRoot))
                && root.equals(expectedRoot)
                && version.equals(expectedVersion);
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
