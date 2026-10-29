package org.zeroj.examples.pedersen.g1.onchain;

import org.julclang.core.PlutusData;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.ScriptContext;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.stdlib.Builtins;
import org.julclang.stdlib.annotation.Entrypoint;
import org.julclang.stdlib.annotation.SpendingValidator;
import org.julclang.stdlib.lib.ContextsLib;
import org.zeroj.onchain.julc.pedersen.lib.PedersenG1Lib;

import java.math.BigInteger;

/**
 * ADR-0060 M4 example validator (experimental, not published): a running total held as a
 * {@code pedersen-bls12-381-g1-v1} commitment in an inline datum, updated by public deltas
 * (spec §6.4).
 *
 * <p>Datum {@code Total(owner, commitment)}: the owner's 28-octet key hash and the 48-octet
 * compressed commitment {@code C = [m]·G + [r]·H}. Redeemer {@code Update(delta)}: a signed
 * integer. The spend is accepted iff
 * <ul>
 *   <li>the owner key hash is exactly 28 octets and the owner signs the transaction;</li>
 *   <li>exactly one input of the transaction is locked by this script's payment credential
 *       (whatever its staking credential), so two totals cannot be updated side by side;</li>
 *   <li>exactly one output is locked by this script's payment credential, it is at the same full
 *       address as the consumed output, and it carries an <b>inline</b> datum
 *       {@code Constr 0 [bytes(28), bytes(48)]}; and</li>
 *   <li>that datum's owner equals the consumed owner and its commitment equals, octet for octet,
 *       {@code encodeCommitment(applyPublicDelta(decodeCommitment(C), delta, 64))}. The library
 *       fails the script on a consumed commitment that is not a canonical subgroup encoding and on
 *       {@code |delta| ≥ 2^64} before any scalar multiplication. Because the expected octets are the
 *       canonical encoding of a valid point, the exact comparison also makes the continuing
 *       commitment canonical.</li>
 * </ul>
 *
 * <p><b>What this example does not provide</b> (spec §6.4, §9, ADR-0060 D9):
 * <ul>
 *   <li><b>Deltas are public.</b> Every update reveals its delta; only the running total's starting
 *       value and blinding stay hidden, and the blinding never changes.</li>
 *   <li><b>Residues, not balances.</b> The total is a residue mod {@code q}: a negative delta can
 *       take it "below zero" to a residue near {@code q}. The application must bound it, for example
 *       by a known starting range, 64-bit deltas and a bounded number of updates; this validator
 *       checks none of that.</li>
 *   <li><b>No value conservation.</b> Nothing ties the lovelace or other assets in the continuing
 *       output to the input, the delta or anything else.</li>
 *   <li><b>No replay protection beyond UTxO consumption</b>, and no issuance control: anyone can pay
 *       to this address with any datum, so a total is only as meaningful as whoever created it.</li>
 *   <li><b>No other context binding.</b> The update is authorized by the owner's signature alone.</li>
 *   <li>Example only. No audit, no production claim.</li>
 * </ul>
 */
@SpendingValidator
public class G1RunningTotalValidator {

    record Total(byte[] owner, byte[] commitment) {}

    record Update(BigInteger delta) {}

    @Entrypoint
    public static boolean validate(Total datum, Update update, ScriptContext ctx) {
        if (Builtins.lengthOfByteString(datum.owner()) != 28L || !signedBy(ctx, datum.owner())) {
            return false;
        }

        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();

        // Count by payment credential, not full address, so a second total held under another
        // staking credential cannot be consumed alongside this one.
        int scriptInputs = 0;
        for (TxInInfo input : ctx.txInfo().inputs()) {
            if (Builtins.equalsData(input.resolved().address().credential(),
                    ownInput.resolved().address().credential())) {
                scriptInputs = scriptInputs + 1;
            } else {
                scriptInputs = scriptInputs;
            }
        }
        if (scriptInputs != 1) return false;

        int continuing = 0;
        boolean sameAddress = true;
        PlutusData next = Builtins.iData(BigInteger.ZERO);
        for (TxOut output : ctx.txInfo().outputs()) {
            if (Builtins.equalsData(output.address().credential(),
                    ownInput.resolved().address().credential())) {
                sameAddress = sameAddress
                        && Builtins.equalsData(output.address(), ownInput.resolved().address());
                next = inlineDatum(output);
                continuing = continuing + 1;
            } else {
                sameAddress = sameAddress;
                next = next;
                continuing = continuing;
            }
        }
        if (continuing != 1 || !sameAddress || !isTotal(next)) return false;

        byte[] expected = PedersenG1Lib.encodeCommitment(PedersenG1Lib.applyPublicDelta(
                PedersenG1Lib.decodeCommitment(datum.commitment()), update.delta(), deltaBits()));
        return Builtins.equalsByteString(totalOwner(next), datum.owner())
                && Builtins.equalsByteString(totalCommitment(next), expected);
    }

    /** The application delta bound: {@code |delta| < 2^64}. */
    private static BigInteger deltaBits() {
        return BigInteger.valueOf(64L);
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
    }

    /** The inline datum; a missing or hashed datum yields an integer, on which {@link #isTotal} fails. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /**
     * {@code Constr 0 [bytes(28), bytes(48)]}. Any other shape either returns false or makes a
     * builtin fail (a non-constructor, a non-bytes field), which rejects the transaction.
     */
    private static boolean isTotal(PlutusData value) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData fields = Builtins.constrFields(value);
        if (Builtins.nullList(fields)) return false;
        PlutusData rest = Builtins.tailList(fields);
        if (Builtins.nullList(rest)) return false;
        return Builtins.nullList(Builtins.tailList(rest))
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(fields))) == 28L
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(rest))) == 48L;
    }

    private static byte[] totalOwner(PlutusData total) {
        return Builtins.unBData(Builtins.headList(Builtins.constrFields(total)));
    }

    private static byte[] totalCommitment(PlutusData total) {
        return Builtins.unBData(Builtins.headList(Builtins.tailList(Builtins.constrFields(total))));
    }
}
