package org.zeroj.examples.notes;

import com.bloxbean.cardano.client.crypto.Blake2bUtil;
import org.julclang.core.PlutusData;
import org.julclang.core.Program;
import org.julclang.ledger.Address;
import org.julclang.ledger.Credential;
import org.julclang.ledger.OutputDatum;
import org.julclang.ledger.PolicyId;
import org.julclang.ledger.ScriptHash;
import org.julclang.ledger.TokenName;
import org.julclang.ledger.TxInInfo;
import org.julclang.ledger.TxOut;
import org.julclang.ledger.TxOutRef;
import org.julclang.ledger.Value;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.ScriptContextTestBuilder;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.zeroj.api.CurveId;
import org.zeroj.circuit.CircuitBuilder;
import org.zeroj.circuit.SignalBuilder;
import org.zeroj.circuit.annotation.ZkBytes;
import org.zeroj.circuit.annotation.ZkContext;
import org.zeroj.circuit.annotation.ZkField;
import org.zeroj.circuit.annotation.ZkUInt;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalEncryption;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.PedersenCommitment;
import org.zeroj.circuit.lib.jubjub.RawElGamalCiphertext;
import org.zeroj.circuit.lib.zk.ZkBlake2b;
import org.zeroj.circuit.lib.zk.ZkElGamal;
import org.zeroj.circuit.lib.zk.ZkElGamalPublicKey;
import org.zeroj.circuit.lib.zk.ZkPedersen;
import org.zeroj.circuit.lib.zk.ZkPedersenCommitment;
import org.zeroj.circuit.r1cs.R1CSConstraintSystem;
import org.zeroj.crypto.groth16.Groth16Keys;
import org.zeroj.examples.notes.onchain.AuditedConfidentialNoteValidator;
import org.zeroj.onchain.julc.groth16.codec.ProverToCardano;
import org.zeroj.onchain.julc.groth16.codec.SnarkjsToCardano;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0055 M5a: the D3a auditor relation (spec §8) on a two-output confidential transfer, proved
 * with Groth16 and verified by {@link AuditedConfidentialNoteValidator} in the Plutus VM, for both
 * public-input layouts.
 *
 * <p>Each created note's amount {@code v = L0 + 2^32·L1} is encrypted limb by limb to the
 * auditor's {@code elgamal-jubjub-v1} key at width 32. The proof ties the limbs to the same amount
 * that opens the note's commitment and balances the transfer. The tests record the constraint
 * count and the validator's CPU and memory against Cardano's per-transaction limits (10,000,000,000
 * steps and 16,500,000 memory units, mainnet, 2026-10-09). ADR-0055 Q5 adopts D3a only within 80%
 * of both. The measurement itself asserts no gate: the ADR records the outcome.
 *
 * <p>The direct layout (spec §8.2) runs in the default test task. The hash-compressed layout
 * (spec §8.3) runs a BLAKE2b gadget of about 3×10^5 constraints and is tagged {@code heavy}; run it
 * with {@code ./gradlew :zeroj-integration-tests:heavyTest --tests '*AuditedConfidentialNote*'}.
 */
class AuditedConfidentialNoteOnChainTest extends ContractTest {

    static final long STEP_LIMIT = 10_000_000_000L;
    static final long MEMORY_LIMIT = 16_500_000L;

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger TWO_32 = BigInteger.ONE.shiftLeft(32);
    private static final byte[] OWNER = filled(28, (byte) 0x0a);
    private static final byte[] RECIPIENT = filled(28, (byte) 0x0b);
    private static final Address SCRIPT_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(filled(28, (byte) 0x5c))), Optional.empty());
    private static final Address REGISTRY_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(filled(28, (byte) 0x7e))), Optional.empty());
    private static final byte[] REGISTRY_POLICY = filled(28, (byte) 0x7f);
    private static final byte[] REGISTRY_TOKEN = "auditor-1".getBytes();
    private static final Value NOTE_VALUE = Value.lovelace(BigInteger.valueOf(2_000_000));

    enum Layout { DIRECT, COMPRESSED }

    /** A note: owner, amount, blinding, commitment, and its two limb encryptions to the auditor. */
    record Note(byte[] owner, long amount, BigInteger blinding, JubjubPoint commitment, List<ElGamalEncryption> limbs) {
        List<BigInteger> audit() {
            List<BigInteger> out = new ArrayList<>();
            for (ElGamalEncryption e : limbs) {
                out.addAll(e.ciphertext().publicInputs()); // A.u, A.v, B.u, B.v (spec §8)
            }
            return out;
        }
    }

    /** One fixture: the auditor, the notes, the circuit and its keys. */
    static final class Fixture {
        final Layout layout;
        final ElGamalSecretKey auditor = ElGamalSecretKey.generate(RANDOM);
        final NOfNKeyContext auditorContext = NOfNKeyContext.singleKey(auditor);
        final Note input;
        final Note out1;
        final Note out2;
        final CircuitBuilder circuit;
        final R1CSConstraintSystem r1cs;
        final Groth16Keys keys;
        final Program program;
        final SnarkjsToCardano.ProofCompressed proof;
        final long proveMillis;

        Fixture(Layout layout, AuditedConfidentialNoteOnChainTest compiler) {
            this.layout = layout;
            input = note(OWNER, 0xfeed_beef_cafeL, auditorContext);
            out1 = note(RECIPIENT, 0xfeed_0000_0001L, auditorContext);
            out2 = note(OWNER, input.amount() - out1.amount(), auditorContext);
            circuit = circuit(layout);
            r1cs = circuit.compileR1CS(CurveId.BLS12_381);
            keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                    BigInteger.valueOf(0xa0d17L));
            var vk = ProverToCardano.compressVk(keys);
            program = compiler.compileValidator(AuditedConfidentialNoteValidator.class, Path.of("src/test/java"))
                    .program()
                    .applyParams(
                            PlutusData.bytes(vk.alpha()),
                            PlutusData.bytes(vk.beta()),
                            PlutusData.bytes(vk.gamma()),
                            PlutusData.bytes(vk.delta()),
                            icData(vk.ic()),
                            PlutusData.bytes(REGISTRY_POLICY),
                            PlutusData.bytes(REGISTRY_TOKEN),
                            PlutusData.integer(layout == Layout.DIRECT ? BigInteger.ZERO : BigInteger.ONE));
            long start = System.nanoTime();
            proof = prove(witness(this, out1, out2));
            proveMillis = (System.nanoTime() - start) / 1_000_000;
        }

        SnarkjsToCardano.ProofCompressed prove(Map<String, List<BigInteger>> w) {
            BigInteger[] full = circuit.calculateWitness(w, CurveId.BLS12_381);
            return ProverToCardano.compressProof(keys.prove(full, r1cs.constraints()));
        }
    }

    static Note note(byte[] owner, long amount, NOfNKeyContext auditor) {
        BigInteger r = PedersenCommitment.randomBlinding(RANDOM);
        BigInteger v = BigInteger.valueOf(amount);
        List<ElGamalEncryption> limbs = List.of(
                ElGamal.encryptWithOpening(auditor, v.mod(TWO_32), 32, RANDOM),
                ElGamal.encryptWithOpening(auditor, v.shiftRight(32), 32, RANDOM));
        return new Note(owner, amount, r, PedersenCommitment.commit(v, r).normalized(), limbs);
    }

    // ------------------------------------------------------------------ circuit

    /**
     * Public: the three commitments, {@code PK_a}, then spec §8.2's 16 coordinates or §8.3's two
     * digest halves. Secret: amounts, blindings, limbs, limb randomness, and for the compressed
     * layout the coordinates and their big-endian bytes.
     */
    static CircuitBuilder circuit(Layout layout) {
        CircuitBuilder b = CircuitBuilder.create("audited-confidential-note-" + layout.name().toLowerCase())
                .publicVar("inU").publicVar("inV")
                .publicVar("out1U").publicVar("out1V")
                .publicVar("out2U").publicVar("out2V")
                .publicVar("pkU").publicVar("pkV");
        if (layout == Layout.DIRECT) {
            for (String c : coordinateNames()) b = b.publicVar(c);
        } else {
            b = b.publicVar("digestHi").publicVar("digestLo");
        }
        b = b.secretVar("inAmount").secretVar("inR")
                .secretVar("out1Amount").secretVar("out1R")
                .secretVar("out2Amount").secretVar("out2R");
        for (int o = 1; o <= 2; o++) {
            for (int j = 0; j <= 1; j++) {
                b = b.secretVar("l" + o + j).secretVar("k" + o + j);
            }
        }
        if (layout == Layout.COMPRESSED) {
            for (String c : coordinateNames()) {
                b = b.secretVar(c);
                for (int k = 0; k < 32; k++) b = b.secretVar(c + "_b" + k);
            }
        }
        return b.defineSignals(cs -> {
            var zk = new ZkContext(cs);
            var inAmount = ZkUInt.secret(cs, "inAmount", 64);
            var in = ZkPedersenCommitment.commit(zk, inAmount, ZkUInt.secret(cs, "inR", 252));
            in.assertAffineEquals(zk, ZkField.publicInput(cs, "inU"), ZkField.publicInput(cs, "inV"));
            var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk,
                    ZkField.publicInput(cs, "pkU"), ZkField.publicInput(cs, "pkV"));
            List<ZkPedersen.Term> outs = new ArrayList<>();
            List<ZkUInt> serialized = new ArrayList<>();
            for (int o = 1; o <= 2; o++) {
                var amount = ZkUInt.secret(cs, "out" + o + "Amount", 64);
                var c = ZkPedersenCommitment.commit(zk, amount, ZkUInt.secret(cs, "out" + o + "R", 252));
                c.assertAffineEquals(zk, ZkField.publicInput(cs, "out" + o + "U"), ZkField.publicInput(cs, "out" + o + "V"));
                outs.add(ZkPedersen.Term.of(c));
                var l0 = ZkUInt.secret(cs, "l" + o + "0", 32);
                var l1 = ZkUInt.secret(cs, "l" + o + "1", 32);
                // One amount: the value that opens C_o is the value the limbs recombine to (spec §8.1).
                l0.asField().add(l1.asField().mul(zk.constant(TWO_32))).assertEqual(amount.asField());
                for (int j = 0; j <= 1; j++) {
                    var ct = ZkElGamal.encrypt(zk, j == 0 ? l0 : l1, ZkUInt.secret(cs, "k" + o + j, 252), key);
                    String[] names = limbCoordinateNames(o, j);
                    ZkField[] coords = new ZkField[4];
                    for (int q = 0; q < 4; q++) {
                        coords[q] = layout == Layout.DIRECT
                                ? ZkField.publicInput(cs, names[q])
                                : ZkField.secret(cs, names[q]);
                    }
                    ct.assertAffineEquals(zk, coords[0], coords[1], coords[2], coords[3]);
                    if (layout == Layout.COMPRESSED) {
                        for (int q = 0; q < 4; q++) serialized.addAll(bigEndianBytes(zk, cs, names[q], coords[q]));
                    }
                }
            }
            ZkPedersen.assertBalanced(zk, List.of(ZkPedersen.Term.of(in)), outs);
            if (layout == Layout.COMPRESSED) {
                ZkBytes digest = ZkBlake2b.hash256(zk, new ZkBytes(serialized));
                halfOf(zk, digest, 0).assertEqual(ZkField.publicInput(cs, "digestHi"));
                halfOf(zk, digest, 16).assertEqual(ZkField.publicInput(cs, "digestLo"));
            }
        });
    }

    /**
     * The 32 bytes of {@code coordinate}, big-endian, each range-checked to 8 bits, whose value
     * equals {@code coordinate} in the field. No in-circuit {@code < p} check is needed: the
     * validator hashes canonical datum coordinates, so a non-canonical byte string yields a
     * different digest and the proof does not verify (collision resistance of BLAKE2b-256).
     */
    private static List<ZkUInt> bigEndianBytes(ZkContext zk, SignalBuilder cs, String name, ZkField coordinate) {
        List<ZkUInt> bytes = new ArrayList<>(32);
        ZkField acc = zk.constant(0);
        for (int k = 0; k < 32; k++) {
            ZkUInt b = ZkUInt.secret(cs, name + "_b" + k, 8);
            bytes.add(b);
            acc = acc.mul(zk.constant(256)).add(b.asField());
        }
        acc.assertEqual(coordinate);
        return bytes;
    }

    /** {@code OS2IP} of 16 digest bytes starting at {@code offset}. */
    private static ZkField halfOf(ZkContext zk, ZkBytes digest, int offset) {
        ZkField acc = zk.constant(0);
        for (int k = 0; k < 16; k++) {
            acc = acc.mul(zk.constant(256)).add(digest.get(offset + k).asField());
        }
        return acc;
    }

    static String[] limbCoordinateNames(int o, int j) {
        String p = "c" + o + j;
        return new String[]{p + "Au", p + "Av", p + "Bu", p + "Bv"};
    }

    static List<String> coordinateNames() {
        List<String> out = new ArrayList<>();
        for (int o = 1; o <= 2; o++) {
            for (int j = 0; j <= 1; j++) out.addAll(List.of(limbCoordinateNames(o, j)));
        }
        return out;
    }

    // ------------------------------------------------------------------ witness

    static Map<String, List<BigInteger>> witness(Fixture f, Note o1, Note o2) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        put(w, "inU", f.input.commitment().affineU());
        put(w, "inV", f.input.commitment().affineV());
        put(w, "inAmount", BigInteger.valueOf(f.input.amount()));
        put(w, "inR", f.input.blinding());
        put(w, "pkU", f.auditor.publicKey().affineU());
        put(w, "pkV", f.auditor.publicKey().affineV());
        Note[] outs = {o1, o2};
        List<BigInteger> coordinates = new ArrayList<>();
        for (int o = 1; o <= 2; o++) {
            Note n = outs[o - 1];
            put(w, "out" + o + "U", n.commitment().affineU());
            put(w, "out" + o + "V", n.commitment().affineV());
            put(w, "out" + o + "Amount", BigInteger.valueOf(n.amount()));
            put(w, "out" + o + "R", n.blinding());
            for (int j = 0; j <= 1; j++) {
                ElGamalEncryption e = n.limbs().get(j);
                put(w, "l" + o + j, e.message());
                put(w, "k" + o + j, e.randomness());
                List<BigInteger> c = e.ciphertext().publicInputs();
                String[] names = limbCoordinateNames(o, j);
                for (int q = 0; q < 4; q++) {
                    put(w, names[q], c.get(q));
                    if (f.layout == Layout.COMPRESSED) {
                        byte[] be = i2osp32(c.get(q));
                        for (int k = 0; k < 32; k++) put(w, names[q] + "_b" + k, BigInteger.valueOf(be[k] & 0xff));
                    }
                }
                coordinates.addAll(c);
            }
        }
        if (f.layout == Layout.COMPRESSED) {
            byte[] digest = digest(coordinates);
            put(w, "digestHi", new BigInteger(1, Arrays.copyOfRange(digest, 0, 16)));
            put(w, "digestLo", new BigInteger(1, Arrays.copyOfRange(digest, 16, 32)));
        }
        return w;
    }

    /** Spec §8.3: BLAKE2b-256 (unkeyed, unpersonalized) over {@code I2OSP(c, 32)} of every coordinate. */
    static byte[] digest(List<BigInteger> coordinates) {
        byte[] bytes = new byte[32 * coordinates.size()];
        for (int i = 0; i < coordinates.size(); i++) {
            System.arraycopy(i2osp32(coordinates.get(i)), 0, bytes, 32 * i, 32);
        }
        return Blake2bUtil.blake2bHash256(bytes);
    }

    private static void put(Map<String, List<BigInteger>> w, String name, BigInteger value) {
        w.put(name, List.of(value));
    }

    // ------------------------------------------------------------------ tests

    @Test
    @DisplayName("Direct layout (spec §8.2): honest transfer verifies; cost, mutations and auditor recovery")
    void directLayout() {
        Fixture f = new Fixture(Layout.DIRECT, this);
        measureAndCheck(f);
        invalidWitnesses(f);
    }

    @Test
    @Tag("heavy")
    @DisplayName("Hash-compressed layout (spec §8.3): honest transfer verifies; cost and mutations")
    void compressedLayout() {
        Fixture f = new Fixture(Layout.COMPRESSED, this);
        measureAndCheck(f);
    }

    private void measureAndCheck(Fixture f) {
        EvalResult honest = evaluate(f.program, context(f, Mutation.NONE));
        assertTrue(honest instanceof EvalResult.Success, "honest transfer: " + honest);
        var budget = honest.budgetConsumed();
        System.out.printf("[D3a %s] constraints=%d publicInputs=%d prove=%d ms cpu=%d (%.1f%% of steps) mem=%d (%.1f%% of memory)%n",
                f.layout, f.r1cs.constraints().size(), f.r1cs.numPublicInputs(), f.proveMillis,
                budget.cpuSteps(), 100.0 * budget.cpuSteps() / STEP_LIMIT,
                budget.memoryUnits(), 100.0 * budget.memoryUnits() / MEMORY_LIMIT);

        for (Mutation m : Mutation.values()) {
            if (m == Mutation.NONE) continue;
            EvalResult r = evaluate(f.program, context(f, m));
            if (r instanceof EvalResult.Success) {
                throw new AssertionError(f.layout + ": mutation " + m + " was accepted");
            }
        }

        // The auditor recovers every created note's amount from the datum alone.
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(TWO_32.longValueExact() - 1);
        for (Note n : List.of(f.out1, f.out2)) {
            List<BigInteger> audit = n.audit();
            long amount = 0;
            for (int j = 1; j >= 0; j--) {
                RawElGamalCiphertext raw = RawElGamalCiphertext.fromAffine(
                        audit.get(4 * j), audit.get(4 * j + 1), audit.get(4 * j + 2), audit.get(4 * j + 3));
                // Admitted on the strength of the transfer proof just verified, which proves R_enc(32).
                ElGamalCiphertext ct = ElGamal.admit(raw, f.auditorContext, 32, statement -> true);
                amount = (amount << 32) | ElGamal.decryptWithSecret(ct, f.auditor, TWO_32.longValueExact() - 1, table);
            }
            assertEquals(n.amount(), amount, "auditor recovers the amount");
        }
    }

    /** ADR-0055 I12: each invalid witness has no satisfying assignment, so no proof exists. */
    private static void invalidWitnesses(Fixture f) {
        // A wrong limb: the encryption is of L0 + 1, but the amount is unchanged.
        Note bumped = withLimb(f.out1, 0, f.out1.limbs().get(0).message().add(BigInteger.ONE), f.auditorContext);
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(witness(f, bumped, f.out2), CurveId.BLS12_381),
                "a limb that does not recombine to the amount");
        // A limb at 2^32 (with L1 lowered to keep the sum): out of the 32-bit range.
        Note overflow = new Note(f.out1.owner(), f.out1.amount(), f.out1.blinding(), f.out1.commitment(), List.of(
                ElGamal.encryptWithOpening(f.auditorContext, f.out1.limbs().get(0).message().add(TWO_32), 33, RANDOM),
                ElGamal.encryptWithOpening(f.auditorContext, f.out1.limbs().get(1).message().subtract(BigInteger.ONE), 32, RANDOM)));
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(witness(f, overflow, f.out2), CurveId.BLS12_381),
                "a limb at or above 2^32");
        // Swapped limbs of one note.
        Note swapped = new Note(f.out1.owner(), f.out1.amount(), f.out1.blinding(), f.out1.commitment(),
                List.of(f.out1.limbs().get(1), f.out1.limbs().get(0)));
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(witness(f, swapped, f.out2), CurveId.BLS12_381),
                "limb ciphertexts swapped");
        // Another key: limbs encrypted to someone else while PK_a is the registry's.
        NOfNKeyContext stranger = NOfNKeyContext.singleKey(ElGamalSecretKey.generate(RANDOM));
        Note elsewhere = note(f.out1.owner(), f.out1.amount(), stranger);
        Note rebound = new Note(f.out1.owner(), f.out1.amount(), f.out1.blinding(), f.out1.commitment(), elsewhere.limbs());
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(witness(f, rebound, f.out2), CurveId.BLS12_381),
                "ciphertexts under another key");
        // A recombination that differs from the committed amount: limbs of v + 1.
        Note other = note(f.out1.owner(), f.out1.amount() + 1, f.auditorContext);
        Note mismatched = new Note(f.out1.owner(), f.out1.amount(), f.out1.blinding(), f.out1.commitment(), other.limbs());
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(witness(f, mismatched, f.out2), CurveId.BLS12_381),
                "limbs of a different amount");
    }

    private static Note withLimb(Note n, int j, BigInteger value, NOfNKeyContext auditor) {
        List<ElGamalEncryption> limbs = new ArrayList<>(n.limbs());
        limbs.set(j, ElGamal.encryptWithOpening(auditor, value, 32, RANDOM));
        return new Note(n.owner(), n.amount(), n.blinding(), n.commitment(), limbs);
    }

    // ------------------------------------------------------------------ validator context

    enum Mutation {
        NONE,
        AUDIT_ABSENT_OUT1, AUDIT_ABSENT_OUT2,
        AUDIT_WRONG_OUT1, AUDIT_WRONG_OUT2,
        AUDIT_SWAPPED_BETWEEN_OUTPUTS, AUDIT_LIMBS_SWAPPED,
        AUDIT_NON_CANONICAL, AUDIT_SEVEN_ENTRIES,
        REGISTRY_MISSING, REGISTRY_OTHER_KEY, REGISTRY_WRONG_TOKEN,
        MISSING_SIGNER, TAMPERED_PROOF
    }

    private PlutusData context(Fixture f, Mutation m) {
        TxOutRef ownRef = TestDataBuilder.randomTxOutRef_typed();
        PlutusData inDatum = noteDatum(f.input, f.input.audit());
        byte[] piA = m == Mutation.TAMPERED_PROOF ? flipped(f.proof.piA()) : f.proof.piA();
        PlutusData redeemer = PlutusData.constr(0,
                PlutusData.bytes(piA), PlutusData.bytes(f.proof.piB()), PlutusData.bytes(f.proof.piC()));
        ScriptContextTestBuilder builder = spendingContext(ownRef, inDatum)
                .input(new TxInInfo(ownRef, txOut(SCRIPT_ADDRESS, NOTE_VALUE, inDatum)))
                .redeemer(redeemer);
        if (m != Mutation.MISSING_SIGNER) builder.signer(OWNER);

        List<BigInteger> a1 = new ArrayList<>(f.out1.audit());
        List<BigInteger> a2 = new ArrayList<>(f.out2.audit());
        switch (m) {
            case AUDIT_WRONG_OUT1 -> a1.set(5, a1.get(5).add(BigInteger.ONE));
            case AUDIT_WRONG_OUT2 -> a2.set(0, a2.get(0).add(BigInteger.ONE));
            case AUDIT_SWAPPED_BETWEEN_OUTPUTS -> {
                List<BigInteger> t = a1;
                a1 = a2;
                a2 = t;
            }
            case AUDIT_LIMBS_SWAPPED -> a1 = concat(a1.subList(4, 8), a1.subList(0, 4));
            case AUDIT_NON_CANONICAL -> a1.set(2, a1.get(2).add(JubjubCurve.BASE_FIELD_PRIME));
            case AUDIT_SEVEN_ENTRIES -> a1 = a1.subList(0, 7);
            default -> { }
        }
        builder.output(txOut(SCRIPT_ADDRESS, NOTE_VALUE, m == Mutation.AUDIT_ABSENT_OUT1
                ? legacyNoteDatum(f.out1) : noteDatum(f.out1, a1)));
        builder.output(txOut(SCRIPT_ADDRESS, NOTE_VALUE, m == Mutation.AUDIT_ABSENT_OUT2
                ? legacyNoteDatum(f.out2) : noteDatum(f.out2, a2)));

        if (m != Mutation.REGISTRY_MISSING) {
            var pk = m == Mutation.REGISTRY_OTHER_KEY
                    ? ElGamalSecretKey.generate(RANDOM).publicKey()
                    : f.auditor.publicKey();
            byte[] token = m == Mutation.REGISTRY_WRONG_TOKEN ? "auditor-2".getBytes() : REGISTRY_TOKEN;
            Value registryValue = Value.lovelace(BigInteger.valueOf(2_000_000))
                    .merge(Value.singleton(PolicyId.of(REGISTRY_POLICY), TokenName.of(token), BigInteger.ONE));
            PlutusData keyDatum = PlutusData.constr(0,
                    PlutusData.integer(pk.affineU()), PlutusData.integer(pk.affineV()));
            builder.referenceInput(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                    txOut(REGISTRY_ADDRESS, registryValue, keyDatum)));
        }
        return builder.buildPlutusData();
    }

    private static PlutusData noteDatum(Note n, List<BigInteger> audit) {
        PlutusData[] entries = new PlutusData[audit.size()];
        for (int i = 0; i < audit.size(); i++) entries[i] = PlutusData.integer(audit.get(i));
        return PlutusData.constr(0,
                PlutusData.bytes(n.owner()),
                PlutusData.integer(n.commitment().affineU()),
                PlutusData.integer(n.commitment().affineV()),
                PlutusData.list(entries));
    }

    /** The ADR-0051 three-field datum, without audit data. */
    private static PlutusData legacyNoteDatum(Note n) {
        return PlutusData.constr(0,
                PlutusData.bytes(n.owner()),
                PlutusData.integer(n.commitment().affineU()),
                PlutusData.integer(n.commitment().affineV()));
    }

    private static TxOut txOut(Address address, Value value, PlutusData datum) {
        return new TxOut(address, value, new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    private static PlutusData icData(List<byte[]> ic) {
        PlutusData[] points = new PlutusData[ic.size()];
        for (int i = 0; i < ic.size(); i++) points[i] = PlutusData.bytes(ic.get(i));
        return PlutusData.list(points);
    }

    private static List<BigInteger> concat(List<BigInteger> a, List<BigInteger> b) {
        List<BigInteger> out = new ArrayList<>(a);
        out.addAll(b);
        return out;
    }

    static byte[] i2osp32(BigInteger x) {
        byte[] raw = x.toByteArray();
        byte[] out = new byte[32];
        int copy = Math.min(raw.length, 32);
        System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
        return out;
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
