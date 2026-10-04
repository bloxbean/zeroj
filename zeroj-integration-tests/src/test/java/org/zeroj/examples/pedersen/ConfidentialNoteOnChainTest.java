package org.zeroj.examples.pedersen;

import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.DatumHash;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PubKeyHash;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.StakingCredential;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.zk.ZkPedersen;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.examples.pedersen.onchain.ConfidentialNoteValidator;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0051 M4: the confidential-note reference application, end to end through the Plutus VM.
 *
 * <p>Circuit ({@code pedersen-jubjub-v1}): the prover opens the input note's commitment and two
 * output commitments (64-bit amounts, 252-bit blindings), binds all three to public affine
 * coordinates, and proves {@code in = out1 + out2} with {@code ZkPedersen.assertBalanced}.
 * Groth16 proof from the pure-Java prover; {@link ConfidentialNoteValidator} evaluated in the
 * Julc VM against constructed script contexts.
 *
 * <p>Covers the ADR's M4 negatives: invalid witnesses cannot be proved, wraparound layouts are
 * refused, and the validator rejects tampered proofs and every binding mutation (signer, consumed
 * datum, output commitments and order, extra script input, output count).
 */
class ConfidentialNoteOnChainTest extends ContractTest {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] OWNER = filled(28, (byte) 0x0a);
    private static final byte[] RECIPIENT = filled(28, (byte) 0x0b);
    private static final Address SCRIPT_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(filled(28, (byte) 0x5c))), Optional.empty());
    private static final Value NOTE_VALUE = Value.lovelace(BigInteger.valueOf(2_000_000));

    private static CircuitBuilder circuit;
    private static R1CSConstraintSystem r1cs;
    private static Groth16Keys keys;
    private static Program program;

    private static Note input;
    private static Note out1;
    private static Note out2;
    private static SnarkjsToCardano.ProofCompressed proof;

    /** A note: its owner, amount, blinding and commitment. */
    record Note(byte[] owner, long amount, BigInteger blinding, JubjubPoint commitment) {
        static Note of(byte[] owner, long amount) {
            BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
            return new Note(owner, amount, r, PedersenCommitment.commit(BigInteger.valueOf(amount), r).normalized());
        }
    }

    @BeforeAll
    static void setup() {
        circuit = transferCircuit(64);
        r1cs = circuit.compileR1CS(CurveId.BLS12_381);
        keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                BigInteger.valueOf(0x4e07e5L));
        var vk = ProverToCardano.compressVk(keys);
        program = new ConfidentialNoteOnChainTest()
                .compileValidator(ConfidentialNoteValidator.class, Path.of("src/test/java"))
                .program()
                .applyParams(
                        PlutusData.bytes(vk.alpha()),
                        PlutusData.bytes(vk.beta()),
                        PlutusData.bytes(vk.gamma()),
                        PlutusData.bytes(vk.delta()),
                        icData(vk.ic()));

        input = Note.of(OWNER, 1_000);
        out1 = Note.of(RECIPIENT, 700);
        out2 = Note.of(OWNER, 300);
        proof = prove(input, out1, out2);
    }

    // ------------------------------------------------------------------
    //  Accepted
    // ------------------------------------------------------------------

    @Test
    @DisplayName("An honest split verifies on-chain")
    void honestSplitVerifies() {
        var result = evaluate(program, context(Mutation.NONE));
        assertSuccess(result);
        System.out.println("[ConfidentialNoteValidator] budget consumed: " + result.budgetConsumed());
    }

    // ------------------------------------------------------------------
    //  Rejected on-chain
    // ------------------------------------------------------------------

    enum Mutation {
        NONE, MISSING_SIGNER, TAMPERED_PROOF, SWAPPED_OUTPUTS, OUTPUT_COMMITMENT, CONSUMED_DATUM,
        EXTRA_SCRIPT_INPUT, EXTRA_STAKED_SCRIPT_INPUT, THREE_OUTPUTS, ONE_OUTPUT, OUTPUT_DATUM_HASH,
        NON_CANONICAL_INPUT, NON_CANONICAL_OUTPUT
    }

    @Test
    @DisplayName("Every tampering and binding mutation is rejected by the validator")
    void mutationsRejected() {
        for (Mutation mutation : Mutation.values()) {
            if (mutation == Mutation.NONE) continue;
            var result = evaluate(program, context(mutation));
            if (result instanceof EvalResult.Success) {
                throw new AssertionError("mutation " + mutation + " was accepted");
            }
        }
    }

    // ------------------------------------------------------------------
    //  Rejected before a proof exists
    // ------------------------------------------------------------------

    @Test
    @DisplayName("An unbalanced split has no witness, so no proof can be produced")
    void unbalancedSplitCannotBeProved() {
        Note greedy = Note.of(RECIPIENT, 701);
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(
                witness(input, greedy, out2), CurveId.BLS12_381));
    }

    /**
     * The ADR-0051 D3a counterexample on the application circuit: the wraparound witness
     * {@code l − 1 = (l − 1 − 5) + 5} is not even expressible with 64-bit amounts, and a layout
     * wide enough to express it is refused when the circuit is defined.
     */
    @Test
    @DisplayName("Wraparound: unrepresentable under 64-bit amounts; 252-bit layouts refused at definition")
    void wraparoundRefused() {
        BigInteger lMinusOne = JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE);
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        var huge = new Note(OWNER, 0, r, PedersenCommitment.commit(lMinusOne, r).normalized());
        Map<String, List<BigInteger>> w = witness(huge, Note.of(RECIPIENT, 5), Note.of(OWNER, 0));
        w.put("inAmount", List.of(lMinusOne));
        assertThrows(ArithmeticException.class, () -> circuit.calculateWitness(w, CurveId.BLS12_381));

        assertThrows(IllegalArgumentException.class, () -> transferCircuit(252),
                "a balance over 252-bit amounts must be refused at definition time");
    }

    // ------------------------------------------------------------------
    //  Harness
    // ------------------------------------------------------------------

    /** inU, inV, out1U, out1V, out2U, out2V public; amounts and blindings secret. */
    static CircuitBuilder transferCircuit(int amountBits) {
        return CircuitBuilder.create("confidential-note-" + amountBits)
                .publicVar("inU").publicVar("inV")
                .publicVar("out1U").publicVar("out1V")
                .publicVar("out2U").publicVar("out2V")
                .secretVar("inAmount").secretVar("inR")
                .secretVar("out1Amount").secretVar("out1R")
                .secretVar("out2Amount").secretVar("out2R")
                .defineSignals(cs -> {
                    var zk = new ZkContext(cs);
                    var in = ZkPedersenCommitment.commit(zk,
                            ZkUInt.secret(cs, "inAmount", amountBits), ZkUInt.secret(cs, "inR", 252));
                    var o1 = ZkPedersenCommitment.commit(zk,
                            ZkUInt.secret(cs, "out1Amount", amountBits), ZkUInt.secret(cs, "out1R", 252));
                    var o2 = ZkPedersenCommitment.commit(zk,
                            ZkUInt.secret(cs, "out2Amount", amountBits), ZkUInt.secret(cs, "out2R", 252));
                    in.assertAffineEquals(zk, ZkField.publicInput(cs, "inU"), ZkField.publicInput(cs, "inV"));
                    o1.assertAffineEquals(zk, ZkField.publicInput(cs, "out1U"), ZkField.publicInput(cs, "out1V"));
                    o2.assertAffineEquals(zk, ZkField.publicInput(cs, "out2U"), ZkField.publicInput(cs, "out2V"));
                    ZkPedersen.assertBalanced(zk,
                            List.of(ZkPedersen.Term.of(in)),
                            List.of(ZkPedersen.Term.of(o1), ZkPedersen.Term.of(o2)));
                });
    }

    static Map<String, List<BigInteger>> witness(Note in, Note o1, Note o2) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        w.put("inU", List.of(in.commitment().affineU()));
        w.put("inV", List.of(in.commitment().affineV()));
        w.put("out1U", List.of(o1.commitment().affineU()));
        w.put("out1V", List.of(o1.commitment().affineV()));
        w.put("out2U", List.of(o2.commitment().affineU()));
        w.put("out2V", List.of(o2.commitment().affineV()));
        w.put("inAmount", List.of(BigInteger.valueOf(in.amount())));
        w.put("inR", List.of(in.blinding()));
        w.put("out1Amount", List.of(BigInteger.valueOf(o1.amount())));
        w.put("out1R", List.of(o1.blinding()));
        w.put("out2Amount", List.of(BigInteger.valueOf(o2.amount())));
        w.put("out2R", List.of(o2.blinding()));
        return w;
    }

    static SnarkjsToCardano.ProofCompressed prove(Note in, Note o1, Note o2) {
        BigInteger[] w = circuit.calculateWitness(witness(in, o1, o2), CurveId.BLS12_381);
        return ProverToCardano.compressProof(keys.prove(w, r1cs.constraints()));
    }

    private PlutusData context(Mutation mutation) {
        TxOutRef ownRef = TestDataBuilder.randomTxOutRef_typed();
        Note consumed = input;
        PlutusData argumentDatum = mutation == Mutation.NON_CANONICAL_INPUT
                ? nonCanonicalNoteDatum(consumed) : noteDatum(consumed);
        TxOut ownOutput = mutation == Mutation.NON_CANONICAL_INPUT
                ? txOut(new OutputDatum.OutputDatumInline(argumentDatum))
                : txOut(noteDatumOutput(mutation == Mutation.CONSUMED_DATUM
                        ? new Note(consumed.owner(), consumed.amount(), consumed.blinding(), out2.commitment())
                        : consumed));

        byte[] piA = mutation == Mutation.TAMPERED_PROOF ? flipped(proof.piA()) : proof.piA();
        PlutusData redeemer = PlutusData.constr(0,
                PlutusData.bytes(piA), PlutusData.bytes(proof.piB()), PlutusData.bytes(proof.piC()));

        ScriptContextTestBuilder builder = spendingContext(ownRef, argumentDatum)
                .input(new TxInInfo(ownRef, ownOutput))
                .redeemer(redeemer);
        if (mutation != Mutation.MISSING_SIGNER) builder.signer(OWNER);

        Note first = mutation == Mutation.SWAPPED_OUTPUTS ? out2 : out1;
        Note second = mutation == Mutation.SWAPPED_OUTPUTS ? out1 : out2;
        if (mutation == Mutation.OUTPUT_COMMITMENT) {
            second = Note.of(OWNER, 300);   // same amount, fresh blinding: a different commitment
        }
        if (mutation == Mutation.OUTPUT_DATUM_HASH) {
            builder.output(new TxOut(SCRIPT_ADDRESS, NOTE_VALUE,
                    new OutputDatum.OutputDatumHash(DatumHash.of(filled(32, (byte) 0x33))),
                    Optional.empty()));
        } else {
            builder.output(txOut(noteDatumOutput(first)));
        }
        if (mutation == Mutation.NON_CANONICAL_OUTPUT) {
            builder.output(txOut(new OutputDatum.OutputDatumInline(nonCanonicalNoteDatum(second))));
        } else if (mutation != Mutation.ONE_OUTPUT) {
            builder.output(txOut(noteDatumOutput(second)));
        }
        if (mutation == Mutation.THREE_OUTPUTS) builder.output(txOut(noteDatumOutput(Note.of(OWNER, 0))));
        if (mutation == Mutation.EXTRA_SCRIPT_INPUT) {
            Note other = Note.of(OWNER, 1_000);
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), txOut(noteDatumOutput(other))));
        }
        if (mutation == Mutation.EXTRA_STAKED_SCRIPT_INPUT) {
            // Same script payment credential, different staking credential.
            Address staked = new Address(SCRIPT_ADDRESS.credential(), Optional.of(new StakingCredential.StakingHash(
                    new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));
            builder.input(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                    new TxOut(staked, NOTE_VALUE, noteDatumOutput(Note.of(OWNER, 1_000)), Optional.empty())));
        }
        return builder.buildPlutusData();
    }

    private static PlutusData noteDatum(Note n) {
        return PlutusData.constr(0,
                PlutusData.bytes(n.owner()),
                PlutusData.integer(n.commitment().affineU()),
                PlutusData.integer(n.commitment().affineV()));
    }

    /** The same point with {@code u + p}: equal mod p, but not a canonical field element. */
    private static PlutusData nonCanonicalNoteDatum(Note n) {
        return PlutusData.constr(0,
                PlutusData.bytes(n.owner()),
                PlutusData.integer(n.commitment().affineU().add(JubjubCurve.BASE_FIELD_PRIME)),
                PlutusData.integer(n.commitment().affineV()));
    }

    private static OutputDatum noteDatumOutput(Note n) {
        return new OutputDatum.OutputDatumInline(noteDatum(n));
    }

    private static TxOut txOut(OutputDatum datum) {
        return new TxOut(SCRIPT_ADDRESS, NOTE_VALUE, datum, Optional.empty());
    }

    private static PlutusData icData(List<byte[]> ic) {
        PlutusData[] points = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) points[i] = PlutusData.bytes(ic.get(i));
        return PlutusData.list(points);
    }

    private static byte[] flipped(byte[] bytes) {
        byte[] copy = bytes.clone();
        copy[copy.length - 1] ^= 1;
        return copy;
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
