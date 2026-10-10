package org.zeroj.examples.notes.onchain;

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
 * ADR-0055 M5a measurement validator: {@code ConfidentialNoteValidator} (ADR-0051 M4) carrying
 * {@code confidential-note-jubjub-v1} deliveries and D3a, enforced auditor access to the amount of
 * every note the spend creates. Test code that measures the design's on-chain cost; it is not a
 * product validator.
 *
 * <p><b>Datum</b> {@code Note(owner, u, v, audit, deliveries)}:
 * <ul>
 *   <li>the owner's key hash and the affine {@code pedersen-jubjub-v1} commitment;</li>
 *   <li>{@code audit}: 8 canonical field elements for one auditor, limb 0 then limb 1, each
 *       {@code A.u, A.v, B.u, B.v} of an {@code elgamal-jubjub-v1} encryption at width 32 (spec
 *       §8.1);</li>
 *   <li>{@code deliveries}: exactly {@code readers} byte strings of 89 bytes each, in reader
 *       order (spec §3.2; ADR-0055 D8). Presence and length are all a validator can check.</li>
 * </ul>
 *
 * <p><b>Spends.</b> With {@code outputs = 2} (a transfer) the spend creates exactly two notes and
 * {@code in = out1 + out2}. With {@code outputs = 1} (a redeem) it creates one change note and
 * {@code in = change + price}, with the price from the redeemer and bound by the proof. Where the
 * price goes on the ledger (paid, burned or minted) is the application's to check, and is not part
 * of the measured cost.
 *
 * <p><b>Auditor key.</b> {@code PK_a} comes from <b>exactly one</b> registry reference input
 * holding <b>exactly one</b> {@code registryPolicy}/{@code registryToken}, with inline datum
 * exactly {@code Constr 0 [I u, I v]}. A second entry, another quantity or another shape fails.
 * That makes the key the current generation's only if the registry token is a singleton that the
 * registry's own script moves forward on rotation: this validator sees only the reference inputs
 * a transaction supplies, so an older entry still unspent could be supplied alone (ADR-0055 Q7,
 * implementation note 11). Possession and subgroup membership are checked at registration (Q6);
 * this validator checks canonical coordinates.
 *
 * <p><b>Fresh randomness.</b> The handles {@code A = [k]·G} of all limb encryptions in the spend
 * must be pairwise distinct. A repeated {@code k} would make {@code B0 − B1 = [L0 − L1]·G} public.
 * This catches exact reuse within the transaction (an honest wallet's accident); related or
 * cross-transaction randomness is not detectable, and rests on the prover's generator.
 *
 * <p><b>Public inputs</b>, all from the ledger or bound by the proof:
 * {@code [in.u, in.v, out1.u, out1.v, (out2.u, out2.v | price), PK.u, PK.v]} followed by either
 * <ul>
 *   <li>{@code compressed = 0} (spec §8.2): the audit coordinates of each created note in output
 *       order; or</li>
 *   <li>{@code compressed = 1} (spec §8.3): {@code digest_hi, digest_lo}, where
 *       {@code digest = blake2b_256(I2OSP(c, 32) ‖ …)} over the same coordinates in the same
 *       order.</li>
 * </ul>
 *
 * <p>Everything else is {@code ConfidentialNoteValidator}'s: the owner signs; exactly one input
 * under this payment credential; the continuing outputs read in output order; every coordinate
 * canonical. Its limits (no issuance control; proofs bound to commitments rather than outputs)
 * apply unchanged.
 *
 * <p><b>Address match.</b> Inputs are counted by payment credential, but continuing outputs are
 * those at the spent note's <b>full</b> address (payment and stake credential). An output under
 * this payment credential with another stake credential is not a continuing output: it is neither
 * counted nor checked, and the spend is accepted. Like any output paid to the script, such a note
 * is unproved issuance, which this validator does not control. An application defines and
 * enforces its own address policy and authenticates its notes (ADR-0055 implementation note 12,
 * M3).
 */
@SpendingValidator
public class AuditedConfidentialNoteValidator {

    @Param static byte[] vkAlpha;
    @Param static byte[] vkBeta;
    @Param static byte[] vkGamma;
    @Param static byte[] vkDelta;
    @Param static PlutusData vkIc;
    @Param static byte[] registryPolicy;
    @Param static byte[] registryToken;
    @Param static BigInteger compressed;
    @Param static BigInteger outputs;
    @Param static BigInteger readers;

    record Note(byte[] owner, BigInteger u, BigInteger v, PlutusData audit, PlutusData deliveries) {}

    record Spend(BigInteger price, byte[] piA, byte[] piB, byte[] piC) {}

    @Entrypoint
    public static boolean validate(Note datum, Spend spend, ScriptContext ctx) {
        if (!signedBy(ctx, datum.owner())) return false;

        var ownInputOptional = ContextsLib.findOwnInput(ctx);
        if (ownInputOptional.isEmpty()) return false;
        TxInInfo ownInput = ownInputOptional.get();
        PlutusData ownNote = inlineDatum(ownInput.resolved());
        if (!isNote(ownNote)
                || !Builtins.equalsByteString(noteOwner(ownNote), datum.owner())
                || !noteU(ownNote).equals(datum.u())
                || !noteV(ownNote).equals(datum.v())) {
            return false;
        }

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
        PlutusData out1 = Builtins.iData(BigInteger.ZERO);
        PlutusData out2 = Builtins.iData(BigInteger.ZERO);
        boolean wellFormed = true;
        for (TxOut output : ctx.txInfo().outputs()) {
            if (Builtins.equalsData(output.address(), ownInput.resolved().address())) {
                PlutusData note = inlineDatum(output);
                wellFormed = wellFormed && isNote(note);
                if (continuing == 0) {
                    out1 = note;
                } else {
                    out1 = out1;
                }
                if (continuing == 1) {
                    out2 = note;
                } else {
                    out2 = out2;
                }
                continuing = continuing + 1;
            } else {
                continuing = continuing;
            }
        }
        if (!wellFormed || !BigInteger.valueOf(continuing).equals(outputs)) return false;
        if (!priceOk(spend.price())) return false;

        // Exactly one registry entry: one token-bearing reference input, quantity 1, Constr 0 [I, I].
        int entries = 0;
        PlutusData key = Builtins.iData(BigInteger.ZERO);
        for (TxInInfo reference : ctx.txInfo().referenceInputs()) {
            TxOut entry = reference.resolved();
            BigInteger quantity = ValuesLib.assetOf(entry.value(), registryPolicy, registryToken);
            if (quantity.equals(BigInteger.ONE)) {
                entries = entries + 1;
                key = inlineDatum(entry);
            } else if (quantity.compareTo(BigInteger.ZERO) > 0) {
                entries = entries + 1;
                key = Builtins.iData(BigInteger.ZERO); // a quantity other than 1 fails isRegistryKey
            } else {
                entries = entries;
                key = key;
            }
        }
        if (entries != 1 || !isRegistryKey(key)) return false;
        BigInteger pkU = Builtins.unIData(Builtins.headList(Builtins.constrFields(key)));
        BigInteger pkV = Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.constrFields(key))));

        PlutusData audit1 = noteAudit(out1);
        if (!distinctHandles(audit1, audit1, true)) return false;
        if (outputs.equals(BigInteger.valueOf(2)) && !distinctAcross(audit1, noteAudit(out2))) return false;
        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(datum.u()),
                Builtins.mkCons(Builtins.iData(datum.v()),
                Builtins.mkCons(Builtins.iData(noteU(out1)),
                Builtins.mkCons(Builtins.iData(noteV(out1)),
                        tailInputs(out2, audit1, spend.price(), pkU, pkV))))));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                spend.piA(), spend.piB(), spend.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    /** A transfer carries no price; a redeem's price is in {@code [1, 2^32)}. */
    private static boolean priceOk(BigInteger price) {
        if (outputs.equals(BigInteger.valueOf(2))) {
            return price.equals(BigInteger.ZERO);
        }
        return price.compareTo(BigInteger.ZERO) > 0 && price.compareTo(BigInteger.valueOf(4294967296L)) < 0;
    }

    /** The public inputs after {@code out1}: {@code out2} or the price, then the key, then the audit data. */
    private static PlutusData tailInputs(PlutusData out2, PlutusData audit1, BigInteger price, BigInteger pkU, BigInteger pkV) {
        if (outputs.equals(BigInteger.valueOf(2))) {
            return Builtins.mkCons(Builtins.iData(noteU(out2)),
                    Builtins.mkCons(Builtins.iData(noteV(out2)),
                    Builtins.mkCons(Builtins.iData(pkU),
                    Builtins.mkCons(Builtins.iData(pkV),
                            auditInputs(audit1, noteAudit(out2))))));
        }
        return Builtins.mkCons(Builtins.iData(price),
                Builtins.mkCons(Builtins.iData(pkU),
                Builtins.mkCons(Builtins.iData(pkV),
                        auditInputs(audit1, Builtins.listData(Builtins.mkNilData())))));
    }

    /**
     * The audit public inputs: spec §8.2 (the coordinates, {@code audit1} then {@code audit2}) or
     * §8.3 (the two digest halves), by {@code compressed}. {@code audit2} is empty for one output.
     */
    private static PlutusData auditInputs(PlutusData audit1, PlutusData audit2) {
        if (compressed.equals(BigInteger.ZERO)) {
            return prependAudit(audit1, Builtins.unListData(audit2));
        }
        byte[] digest = Builtins.blake2b_256(Builtins.appendByteString(auditBytes(audit1), auditBytes(audit2)));
        return Builtins.mkCons(Builtins.iData(Builtins.byteStringToInteger(true, Builtins.sliceByteString(0, 16, digest))),
                Builtins.mkCons(Builtins.iData(Builtins.byteStringToInteger(true, Builtins.sliceByteString(16, 16, digest))),
                        Builtins.mkNilData()));
    }

    /** {@code audit1}'s 8 entries prepended to the list {@code rest}. */
    private static PlutusData prependAudit(PlutusData audit1, PlutusData rest) {
        PlutusData a0 = Builtins.unListData(audit1);
        PlutusData a1 = Builtins.tailList(a0);
        PlutusData a2 = Builtins.tailList(a1);
        PlutusData a3 = Builtins.tailList(a2);
        PlutusData a4 = Builtins.tailList(a3);
        PlutusData a5 = Builtins.tailList(a4);
        PlutusData a6 = Builtins.tailList(a5);
        PlutusData a7 = Builtins.tailList(a6);
        return Builtins.mkCons(Builtins.headList(a0),
                Builtins.mkCons(Builtins.headList(a1),
                Builtins.mkCons(Builtins.headList(a2),
                Builtins.mkCons(Builtins.headList(a3),
                Builtins.mkCons(Builtins.headList(a4),
                Builtins.mkCons(Builtins.headList(a5),
                Builtins.mkCons(Builtins.headList(a6),
                Builtins.mkCons(Builtins.headList(a7),
                        rest))))))));
    }

    /** {@code I2OSP(c, 32)} of the audit coordinates, concatenated in order (empty for an empty list). */
    private static byte[] auditBytes(PlutusData audit) {
        byte[] out = Builtins.integerToByteString(true, 0, BigInteger.ZERO);
        PlutusData rest = Builtins.unListData(audit);
        while (!Builtins.nullList(rest)) {
            out = Builtins.appendByteString(out,
                    Builtins.integerToByteString(true, 32, Builtins.unIData(Builtins.headList(rest))));
            rest = Builtins.tailList(rest);
        }
        return out;
    }

    /**
     * With {@code sameNote}, the two limb handles of note {@code a} differ. Otherwise no handle of
     * {@code a} equals a handle of {@code b}. A handle is the point {@code (A.u, A.v)}.
     */
    private static boolean distinctHandles(PlutusData a, PlutusData b, boolean sameNote) {
        PlutusData x = Builtins.unListData(a);
        PlutusData xa0u = Builtins.headList(x);
        PlutusData xa0v = Builtins.headList(Builtins.tailList(x));
        PlutusData x4 = Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(x))));
        PlutusData xa1u = Builtins.headList(x4);
        PlutusData xa1v = Builtins.headList(Builtins.tailList(x4));
        if (sameNote) {
            return !(Builtins.equalsData(xa0u, xa1u) && Builtins.equalsData(xa0v, xa1v));
        }
        PlutusData y = Builtins.unListData(b);
        PlutusData ya0u = Builtins.headList(y);
        PlutusData ya0v = Builtins.headList(Builtins.tailList(y));
        PlutusData y4 = Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.tailList(y))));
        PlutusData ya1u = Builtins.headList(y4);
        PlutusData ya1v = Builtins.headList(Builtins.tailList(y4));
        return !(Builtins.equalsData(xa0u, ya0u) && Builtins.equalsData(xa0v, ya0v))
                && !(Builtins.equalsData(xa0u, ya1u) && Builtins.equalsData(xa0v, ya1v))
                && !(Builtins.equalsData(xa1u, ya0u) && Builtins.equalsData(xa1v, ya0v))
                && !(Builtins.equalsData(xa1u, ya1u) && Builtins.equalsData(xa1v, ya1v));
    }

    /** All four handles of two notes are pairwise distinct (each note's own pair is checked separately). */
    private static boolean distinctAcross(PlutusData audit1, PlutusData audit2) {
        return distinctHandles(audit2, audit2, true) && distinctHandles(audit1, audit2, false);
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
    }

    /** The inline datum; a missing or hashed datum yields an integer, which the shape checks reject. */
    private static PlutusData inlineDatum(TxOut output) {
        return switch (output.datum()) {
            case OutputDatum.OutputDatumInline inline -> inline.datum();
            case OutputDatum.OutputDatumHash ignored -> Builtins.iData(BigInteger.ZERO);
            case OutputDatum.NoOutputDatum ignored -> Builtins.iData(BigInteger.ZERO);
        };
    }

    /** {@code Constr 0 [I u, I v]}, both canonical, exactly two fields. */
    private static boolean isRegistryKey(PlutusData key) {
        if (Builtins.constrTag(key) != 0) return false;
        PlutusData fields = Builtins.constrFields(key);
        PlutusData rest = Builtins.tailList(fields);
        return Builtins.nullList(Builtins.tailList(rest))
                && canonicalField(Builtins.unIData(Builtins.headList(fields)))
                && canonicalField(Builtins.unIData(Builtins.headList(rest)));
    }

    /**
     * {@code Constr 0 [bytes(28), int, int, list of exactly 8 canonical ints, list of exactly
     * readers 89-byte strings]}, with canonical commitment coordinates. Any other shape returns
     * false or makes a builtin fail (fail closed).
     */
    private static boolean isNote(PlutusData value) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData fields = Builtins.constrFields(value);
        PlutusData f1 = Builtins.tailList(fields);
        PlutusData f2 = Builtins.tailList(f1);
        PlutusData f3 = Builtins.tailList(f2);
        PlutusData f4 = Builtins.tailList(f3);
        if (!Builtins.nullList(Builtins.tailList(f4))) return false;
        if (Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(fields))) != 28) return false;
        if (!canonicalField(Builtins.unIData(Builtins.headList(f1)))) return false;
        if (!canonicalField(Builtins.unIData(Builtins.headList(f2)))) return false;
        int count = 0;
        boolean canonical = true;
        PlutusData rest = Builtins.unListData(Builtins.headList(f3));
        while (!Builtins.nullList(rest)) {
            canonical = canonical && canonicalField(Builtins.unIData(Builtins.headList(rest)));
            count = count + 1;
            rest = Builtins.tailList(rest);
        }
        if (!canonical || count != 8) return false;
        int deliveries = 0;
        boolean lengths = true;
        PlutusData each = Builtins.unListData(Builtins.headList(f4));
        while (!Builtins.nullList(each)) {
            lengths = lengths && Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(each))) == 89;
            deliveries = deliveries + 1;
            each = Builtins.tailList(each);
        }
        return lengths && BigInteger.valueOf(deliveries).equals(readers);
    }

    private static byte[] noteOwner(PlutusData note) {
        return Builtins.unBData(Builtins.headList(Builtins.constrFields(note)));
    }

    private static BigInteger noteU(PlutusData note) {
        return Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.constrFields(note))));
    }

    private static BigInteger noteV(PlutusData note) {
        return Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.constrFields(note)))));
    }

    private static PlutusData noteAudit(PlutusData note) {
        return Builtins.headList(Builtins.tailList(Builtins.tailList(Builtins.tailList(Builtins.constrFields(note)))));
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
