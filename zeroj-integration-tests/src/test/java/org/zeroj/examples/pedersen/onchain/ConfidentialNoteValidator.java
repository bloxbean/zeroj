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
import org.zeroj.onchain.julc.groth16.lib.Groth16BLS12381Lib;

import java.math.BigInteger;

/**
 * ADR-0051 M4 reference validator: a confidential note whose amount is a
 * {@code pedersen-jubjub-v1} commitment.
 *
 * <p>Datum {@code Note(owner, u, v)}: the owner's key hash and the affine commitment to the
 * note's amount. Spending splits one note into exactly two notes at the same script address. The
 * redeemer carries only the Groth16 proof; every public input is taken from the ledger, never
 * from the redeemer:
 * {@code [in.u, in.v, out1.u, out1.v, out2.u, out2.v]} — the consumed note's datum and the two
 * continuing outputs' inline datums, in output order. The circuit proves that the prover knows
 * openings of all three commitments with 64-bit amounts and {@code in = out1 + out2} as integers
 * ({@code ZkPedersen.assertBalanced}).
 *
 * <p>What this validator binds, and why (AGENTS.md: proof validity is not authorization):
 * <ul>
 *   <li><b>Authorization:</b> the consumed note's owner must sign.</li>
 *   <li><b>State binding:</b> the input commitment comes from the consumed datum; the output
 *       commitments from the continuing outputs. A proof for other commitments fails.</li>
 *   <li><b>Double satisfaction:</b> exactly one input locked by this script's payment credential
 *       (whatever its staking credential), so two notes cannot be spent in one transaction.</li>
 *   <li><b>Spend once:</b> a note is an unspent output and can be consumed once.</li>
 *   <li><b>Canonical inputs:</b> every public input is checked to be a field element.</li>
 * </ul>
 *
 * <p><b>What it does not provide</b> — this is a reference for statement and context binding, not
 * a complete asset system:
 * <ul>
 *   <li><b>No issuance control.</b> Anyone can pay to this address with any {@code Note} datum, so
 *       conservation holds per spend ({@code in = out1 + out2}) but there is no supply guarantee:
 *       nothing limits which input commitments exist. A real system mints notes under a policy or
 *       state token that enforces its own rules.</li>
 *   <li><b>The proof is bound to commitments, not to an output or an owner.</b> A proof for
 *       {@code (in, out1, out2)} also verifies for any other note carrying the same input
 *       commitment. Copying a victim's commitment into one's own note lets that proof split it into
 *       the victim's output commitments — which the copier cannot open, so nothing is stolen, but
 *       proofs are not unique to a UTxO. Bind the consumed output reference or the owner into the
 *       statement if an application needs that.</li>
 *   <li>Asset custody — what the notes are worth outside the commitments — is application-specific
 *       and out of scope.</li>
 * </ul>
 */
@SpendingValidator
public class ConfidentialNoteValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;

    record Note(byte[] owner, BigInteger u, BigInteger v) {}

    record Transfer(byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(Note datum, Transfer transfer, ScriptContext ctx) {
        if (!canonicalField(datum.u()) || !canonicalField(datum.v())
                || !signedBy(ctx, datum.owner())) {
            return false;
        }

        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        if (!hasNoteDatum(ownInput.resolved(), datum.owner(), datum.u(), datum.v())) return false;

        // Count by payment credential, not full address, so notes held under different staking
        // credentials cannot be spent side by side.
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
        BigInteger out1u = BigInteger.ZERO;
        BigInteger out1v = BigInteger.ZERO;
        BigInteger out2u = BigInteger.ZERO;
        BigInteger out2v = BigInteger.ZERO;
        boolean wellFormed = true;
        for (TxOut output : ctx.txInfo().outputs()) {
            if (Builtins.equalsData(output.address(), ownInput.resolved().address())) {
                PlutusData note = inlineDatum(output);
                boolean ok = isNote(note);
                wellFormed = wellFormed && ok;
                if (ok && continuing == 0) {
                    out1u = noteU(note);
                    out1v = noteV(note);
                } else {
                    out1u = out1u;
                    out1v = out1v;
                }
                if (ok && continuing == 1) {
                    out2u = noteU(note);
                    out2v = noteV(note);
                } else {
                    out2u = out2u;
                    out2v = out2v;
                }
                continuing = continuing + 1;
            } else {
                continuing = continuing;
            }
        }
        if (continuing != 2 || !wellFormed
                || !canonicalField(out1u) || !canonicalField(out1v)
                || !canonicalField(out2u) || !canonicalField(out2v)) {
            return false;
        }

        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(datum.u()),
                Builtins.mkCons(Builtins.iData(datum.v()),
                Builtins.mkCons(Builtins.iData(out1u),
                Builtins.mkCons(Builtins.iData(out1v),
                Builtins.mkCons(Builtins.iData(out2u),
                Builtins.mkCons(Builtins.iData(out2v),
                        Builtins.mkNilData())))))));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                transfer.piA(), transfer.piB(), transfer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
    }

    private static boolean hasNoteDatum(TxOut output, byte[] owner, BigInteger u, BigInteger v) {
        PlutusData note = inlineDatum(output);
        return isNote(note)
                && Builtins.equalsByteString(noteOwner(note), owner)
                && noteU(note).equals(u)
                && noteV(note).equals(v);
    }

    /** The inline datum; a missing or hashed datum yields an integer, which {@link #isNote} rejects. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /**
     * {@code Constr 0 [bytes(28), int, int]}. Any other shape — a different constructor, field
     * count or field type — either returns false or makes a builtin fail, which rejects the
     * transaction (fail closed).
     */
    private static boolean isNote(PlutusData value) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData fields = Builtins.constrFields(value);
        if (Builtins.nullList(fields)) return false;
        PlutusData rest = Builtins.tailList(fields);
        if (Builtins.nullList(rest)) return false;
        PlutusData rest2 = Builtins.tailList(rest);
        if (Builtins.nullList(rest2)) return false;
        return Builtins.nullList(Builtins.tailList(rest2))
                && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(fields))) == 28
                && Builtins.unIData(Builtins.headList(rest)).compareTo(BigInteger.ZERO) >= 0
                && Builtins.unIData(Builtins.headList(rest2)).compareTo(BigInteger.ZERO) >= 0;
    }

    private static byte[] noteOwner(PlutusData note) {
        return Builtins.unBData(Builtins.headList(Builtins.constrFields(note)));
    }

    private static BigInteger noteU(PlutusData note) {
        return Builtins.asInteger(Builtins.headList(Builtins.tailList(Builtins.constrFields(note))));
    }

    private static BigInteger noteV(PlutusData note) {
        return Builtins.asInteger(Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.constrFields(note)))));
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
