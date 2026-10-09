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
 * ADR-0055 M5a measurement validator: {@code ConfidentialNoteValidator} (ADR-0051 M4) extended
 * with D3a, enforced auditor access to the amount of every note the transfer creates.
 *
 * <p><b>Datum</b> {@code Note(owner, u, v, audit)}: the owner's key hash, the affine
 * {@code pedersen-jubjub-v1} commitment, and the note's D3a audit data for one auditor. The audit
 * data is a list of 8 canonical field elements: limb 0 then limb 1, each {@code A.u, A.v, B.u, B.v}
 * of an {@code elgamal-jubjub-v1} encryption at width 32 (spec §8.1). The note's delivery bytes
 * ({@code confidential-note-jubjub-v1} §3.2) would sit beside them; they are not inputs to the
 * proof and do not change the measured cost, so this measurement omits them.
 *
 * <p><b>Auditor key.</b> The auditor's {@code elgamal-jubjub-v1} key {@code PK_a} comes from a
 * registry <b>reference input</b> that holds the {@code registryPolicy}/{@code registryToken}
 * asset, with inline datum {@code Constr 0 [I u, I v]}. That makes the key generation the
 * registry's to govern, and enforceable (ADR-0055 Q7). The registry's governance checks possession
 * and subgroup membership at registration (Q6); this validator checks only canonical coordinates.
 *
 * <p><b>Public inputs</b>, all from the ledger (never the redeemer):
 * {@code [in.u, in.v, out1.u, out1.v, out2.u, out2.v, PK.u, PK.v]} followed by either:
 * <ul>
 *   <li>{@code compressed = 0} (spec §8.2): {@code out1.audit[0..7], out2.audit[0..7]};</li>
 *   <li>{@code compressed = 1} (spec §8.3): {@code digest_hi, digest_lo}, where
 *       {@code digest = blake2b_256(I2OSP(c, 32) ‖ …)} over the same 16 coordinates in the same
 *       order.</li>
 * </ul>
 *
 * <p>Everything else is {@code ConfidentialNoteValidator}'s: the owner signs; exactly one input
 * under this payment credential; exactly two continuing outputs, read in output order; every
 * coordinate canonical. Its limits (no issuance control; proofs bound to commitments rather than
 * outputs) apply unchanged. This is test code that measures D3a's cost; it is not a product
 * validator.
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

    record Note(byte[] owner, BigInteger u, BigInteger v, PlutusData audit) {}

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
        if (continuing != 2 || !wellFormed) return false;

        // The auditor key from the registry reference input.
        boolean found = false;
        BigInteger pkU = BigInteger.ZERO;
        BigInteger pkV = BigInteger.ZERO;
        for (TxInInfo reference : ctx.txInfo().referenceInputs()) {
            TxOut entry = reference.resolved();
            boolean isRegistry = ValuesLib.assetOf(entry.value(), registryPolicy, registryToken)
                    .compareTo(BigInteger.ZERO) > 0;
            if (isRegistry && !found) {
                PlutusData key = inlineDatum(entry);
                found = Builtins.constrTag(key) == 0;
                pkU = Builtins.unIData(Builtins.headList(Builtins.constrFields(key)));
                pkV = Builtins.unIData(Builtins.headList(Builtins.tailList(Builtins.constrFields(key))));
            } else {
                found = found;
                pkU = pkU;
                pkV = pkV;
            }
        }
        if (!found || !canonicalField(pkU) || !canonicalField(pkV)) return false;

        PlutusData tail = auditInputs(noteAudit(out1), noteAudit(out2));

        PlutusData publicInputs = Builtins.listData(
                Builtins.mkCons(Builtins.iData(datum.u()),
                Builtins.mkCons(Builtins.iData(datum.v()),
                Builtins.mkCons(Builtins.iData(noteU(out1)),
                Builtins.mkCons(Builtins.iData(noteV(out1)),
                Builtins.mkCons(Builtins.iData(noteU(out2)),
                Builtins.mkCons(Builtins.iData(noteV(out2)),
                Builtins.mkCons(Builtins.iData(pkU),
                Builtins.mkCons(Builtins.iData(pkV),
                        tail)))))))));
        return Groth16BLS12381Lib.verify(
                publicInputs,
                transfer.piA(), transfer.piB(), transfer.piC(),
                vkAlpha, vkBeta, vkGamma, vkDelta, vkIc);
    }

    /** The public inputs after the auditor key: spec §8.2 or §8.3, by {@code compressed}. */
    private static PlutusData auditInputs(PlutusData audit1, PlutusData audit2) {
        if (compressed.equals(BigInteger.ZERO)) {
            // Spec §8.2: out1's 8 coordinates, then out2's (already a list of canonical integers).
            return prependAudit(audit1, audit2);
        }
        // Spec §8.3: blake2b_256 over I2OSP(c, 32) of the same 16 coordinates, split in halves.
        byte[] digest = Builtins.blake2b_256(Builtins.appendByteString(auditBytes(audit1), auditBytes(audit2)));
        return Builtins.mkCons(Builtins.iData(Builtins.byteStringToInteger(true, Builtins.sliceByteString(0, 16, digest))),
                Builtins.mkCons(Builtins.iData(Builtins.byteStringToInteger(true, Builtins.sliceByteString(16, 16, digest))),
                        Builtins.mkNilData()));
    }

    /** {@code audit1}'s 8 entries prepended to the list {@code audit2}. */
    private static PlutusData prependAudit(PlutusData audit1, PlutusData audit2) {
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
                        Builtins.unListData(audit2)))))))));
    }

    /** {@code I2OSP(c, 32)} of the 8 audit coordinates, concatenated in order. */
    private static byte[] auditBytes(PlutusData audit) {
        byte[] out = Builtins.integerToByteString(true, 0, BigInteger.ZERO);
        PlutusData rest = Builtins.unListData(audit);
        while (!Builtins.nullList(rest)) {
            out = Builtins.appendByteString(out,
                    Builtins.integerToByteString(true, 32, Builtins.unIData(Builtins.headList(rest))));
            rest = Builtins.tailList(rest);
        }
        return out; // isNote has already required exactly 8 entries
    }

    private static boolean signedBy(ScriptContext ctx, byte[] owner) {
        boolean found = false;
        for (var signer : ctx.txInfo().signatories()) {
            found = found || Builtins.equalsByteString(signer.hash(), owner);
        }
        return found;
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
     * {@code Constr 0 [bytes(28), int, int, list of exactly 8 ints]}, every integer canonical.
     * Any other shape returns false or makes a builtin fail (fail closed).
     */
    private static boolean isNote(PlutusData value) {
        if (Builtins.constrTag(value) != 0) return false;
        PlutusData fields = Builtins.constrFields(value);
        PlutusData f1 = Builtins.tailList(fields);
        PlutusData f2 = Builtins.tailList(f1);
        PlutusData f3 = Builtins.tailList(f2);
        if (!Builtins.nullList(Builtins.tailList(f3))) return false;
        if (Builtins.lengthOfByteString(Builtins.unBData(Builtins.headList(fields))) != 28) return false;
        if (!canonicalField(Builtins.unIData(Builtins.headList(f1)))) return false;
        if (!canonicalField(Builtins.unIData(Builtins.headList(f2)))) return false;
        PlutusData audit = Builtins.unListData(Builtins.headList(f3));
        int count = 0;
        boolean canonical = true;
        PlutusData rest = audit;
        while (!Builtins.nullList(rest)) {
            canonical = canonical && canonicalField(Builtins.unIData(Builtins.headList(rest)));
            count = count + 1;
            rest = Builtins.tailList(rest);
        }
        return canonical && count == 8;
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
