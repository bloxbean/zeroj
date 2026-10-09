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
import org.zeroj.circuit.lib.jubjub.ConfidentialNotes;
import org.zeroj.circuit.lib.jubjub.ElGamal;
import org.zeroj.circuit.lib.jubjub.ElGamalCiphertext;
import org.zeroj.circuit.lib.jubjub.ElGamalPublicKey;
import org.zeroj.circuit.lib.jubjub.ElGamalSecretKey;
import org.zeroj.circuit.lib.jubjub.JubjubCurve;
import org.zeroj.circuit.lib.jubjub.JubjubDiscreteLog;
import org.zeroj.circuit.lib.jubjub.JubjubPoint;
import org.zeroj.circuit.lib.jubjub.NOfNKeyContext;
import org.zeroj.circuit.lib.jubjub.NoteOpening;
import org.zeroj.circuit.lib.jubjub.NoteScanner;
import org.zeroj.circuit.lib.jubjub.NoteViewingKey;
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
 * ADR-0055 M5a: confidential notes carrying {@code confidential-note-jubjub-v1} deliveries and the
 * D3a auditor relation (spec §8), proved with Groth16 and verified by
 * {@link AuditedConfidentialNoteValidator} in the Julc VM (Plutus V3, protocol version 11 cost
 * model), for a two-output transfer and a one-output redeem, in both public-input layouts.
 *
 * <p>Each created note carries its commitment, its two 32-bit limb encryptions to the auditor's
 * {@code elgamal-jubjub-v1} key, and two deliveries (owner, then auditor). The proof ties the limbs
 * to the same amount that opens the note's commitment and balances the spend. The tests record the
 * constraint count, prover time and the validator's CPU and memory against Cardano's
 * per-transaction limits (10,000,000,000 steps and 16,500,000 memory units, mainnet, 2026-10-09);
 * ADR-0055 Q5 adopts D3a within 80% of both. The measurement asserts no gate: the ADR records the
 * outcome. Owner and auditor then recover every created note from the datum alone.
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
    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
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

    enum Shape {
        TRANSFER(2), REDEEM(1);

        final int outputs;

        Shape(int outputs) {
            this.outputs = outputs;
        }
    }

    /** One limb encryption {@code A = [k]·G}, {@code B = [m]·G + [k]·PK}, with its opening. */
    record Limb(BigInteger m, BigInteger k, List<BigInteger> coordinates) {
        static Limb of(BigInteger m, BigInteger k, JubjubPoint pk) {
            JubjubPoint g = JubjubPoint.SUBGROUP_GENERATOR;
            JubjubPoint a = g.scalarMul(k).normalized();
            JubjubPoint b = g.scalarMul(m).add(pk.scalarMul(k)).normalized();
            return new Limb(m, k, List.of(a.affineU(), a.affineV(), b.affineU(), b.affineV()));
        }
    }

    /** A note: owner, amount, opening, commitment, limb encryptions and deliveries. */
    record Note(byte[] owner, long amount, NoteOpening opening, JubjubPoint commitment, List<Limb> limbs,
                List<byte[]> deliveries) {
        List<BigInteger> audit() {
            List<BigInteger> out = new ArrayList<>();
            for (Limb l : limbs) out.addAll(l.coordinates());
            return out;
        }

        Note withLimbs(List<Limb> other) {
            return new Note(owner, amount, opening, commitment, other, deliveries);
        }
    }

    /** One fixture: the keys, the notes, the circuit, its keys and the honest proof. */
    static final class Fixture {
        final Layout layout;
        final Shape shape;
        final ElGamalSecretKey auditor = ElGamalSecretKey.generate(RANDOM);
        final NoteViewingKey auditorView = NoteViewingKey.generate(RANDOM);
        final NoteViewingKey ownerView = NoteViewingKey.generate(RANDOM);
        final NoteViewingKey recipientView = NoteViewingKey.generate(RANDOM);
        final Note input;
        final List<Note> outs;
        final long price;
        final CircuitBuilder circuit;
        final R1CSConstraintSystem r1cs;
        final Groth16Keys keys;
        final Program program;
        final SnarkjsToCardano.ProofCompressed proof;
        final long proveMillis;

        Fixture(Layout layout, Shape shape, AuditedConfidentialNoteOnChainTest compiler) {
            this.layout = layout;
            this.shape = shape;
            input = note(OWNER, 0xfeed_beef_cafeL, ownerView);
            if (shape == Shape.TRANSFER) {
                price = 0;
                Note out1 = note(RECIPIENT, 0xfeed_0000_0001L, recipientView);
                outs = List.of(out1, note(OWNER, input.amount() - out1.amount(), ownerView));
            } else {
                price = 120_000L;
                outs = List.of(note(OWNER, input.amount() - price, ownerView));
            }
            circuit = circuit(layout, shape);
            r1cs = circuit.compileR1CS(CurveId.BLS12_381);
            keys = Groth16Keys.setupInMemory(r1cs.constraints(), r1cs.numWires(), r1cs.numPublicInputs(),
                    BigInteger.valueOf(0xa0d17L + shape.ordinal()));
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
                            PlutusData.integer(layout == Layout.DIRECT ? BigInteger.ZERO : BigInteger.ONE),
                            PlutusData.integer(BigInteger.valueOf(shape.outputs)),
                            PlutusData.integer(BigInteger.TWO));
            long start = System.nanoTime();
            proof = prove(witness(this, outs));
            proveMillis = (System.nanoTime() - start) / 1_000_000;
        }

        JubjubPoint pk() {
            return auditor.publicKey().point();
        }

        Note note(byte[] owner, long amount, NoteViewingKey ownerKey) {
            NoteOpening opening = NoteOpening.random(BigInteger.valueOf(amount), RANDOM);
            BigInteger v = opening.value();
            List<Limb> limbs = List.of(
                    Limb.of(v.mod(TWO_32), PedersenCommitment.randomBlinding(RANDOM), pk()),
                    Limb.of(v.shiftRight(32), PedersenCommitment.randomBlinding(RANDOM), pk()));
            List<byte[]> deliveries = ConfidentialNotes.seal(opening,
                    List.of(ownerKey.readerKey(), auditorView.readerKey()), RANDOM);
            return new Note(owner, amount, opening, opening.commitment().normalized(), limbs, deliveries);
        }

        SnarkjsToCardano.ProofCompressed prove(Map<String, List<BigInteger>> w) {
            BigInteger[] full = circuit.calculateWitness(w, CurveId.BLS12_381);
            return ProverToCardano.compressProof(keys.prove(full, r1cs.constraints()));
        }
    }

    // ------------------------------------------------------------------ circuit

    /**
     * Public: the input and created commitments, the price for a redeem, {@code PK_a}, then spec
     * §8.2's coordinates or §8.3's two digest halves. Secret: amounts, blindings, limbs, limb
     * randomness, and for the compressed layout the coordinates and their big-endian bytes.
     */
    static CircuitBuilder circuit(Layout layout, Shape shape) {
        int n = shape.outputs;
        CircuitBuilder b = CircuitBuilder.create("audited-note-" + shape.name().toLowerCase() + "-" + layout.name().toLowerCase())
                .publicVar("inU").publicVar("inV")
                .publicVar("out1U").publicVar("out1V");
        b = n == 2 ? b.publicVar("out2U").publicVar("out2V") : b.publicVar("price");
        b = b.publicVar("pkU").publicVar("pkV");
        if (layout == Layout.DIRECT) {
            for (String c : coordinateNames(n)) b = b.publicVar(c);
        } else {
            b = b.publicVar("digestHi").publicVar("digestLo");
        }
        b = b.secretVar("inAmount").secretVar("inR");
        for (int o = 1; o <= n; o++) {
            b = b.secretVar("out" + o + "Amount").secretVar("out" + o + "R");
            for (int j = 0; j <= 1; j++) b = b.secretVar("l" + o + j).secretVar("k" + o + j);
        }
        if (layout == Layout.COMPRESSED) {
            for (String c : coordinateNames(n)) {
                b = b.secretVar(c);
                for (int k = 0; k < 32; k++) b = b.secretVar(c + "_b" + k);
            }
        }
        return b.defineSignals(cs -> {
            var zk = new ZkContext(cs);
            var in = ZkPedersenCommitment.commit(zk, ZkUInt.secret(cs, "inAmount", 64), ZkUInt.secret(cs, "inR", 252));
            in.assertAffineEquals(zk, ZkField.publicInput(cs, "inU"), ZkField.publicInput(cs, "inV"));
            var key = ZkElGamalPublicKey.fromVerifierFixedPublic(zk,
                    ZkField.publicInput(cs, "pkU"), ZkField.publicInput(cs, "pkV"));
            List<ZkPedersen.Term> outs = new ArrayList<>();
            List<ZkUInt> serialized = new ArrayList<>();
            for (int o = 1; o <= n; o++) {
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
                        coords[q] = layout == Layout.DIRECT ? ZkField.publicInput(cs, names[q]) : ZkField.secret(cs, names[q]);
                    }
                    ct.assertAffineEquals(zk, coords[0], coords[1], coords[2], coords[3]);
                    if (layout == Layout.COMPRESSED) {
                        for (int q = 0; q < 4; q++) serialized.addAll(bigEndianBytes(zk, cs, names[q], coords[q]));
                    }
                }
            }
            if (n == 1) outs.add(ZkPedersen.Term.amount(ZkUInt.publicInput(cs, "price", 32)));
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
     * validator hashes canonical datum coordinates, so a non-canonical byte string (the bytes of
     * {@code c + p}) yields a different digest and the proof does not verify (ADR-0055
     * implementation note 7; {@code compressedBinding} tests it).
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
        for (int k = 0; k < 16; k++) acc = acc.mul(zk.constant(256)).add(digest.get(offset + k).asField());
        return acc;
    }

    static String[] limbCoordinateNames(int o, int j) {
        String p = "c" + o + j;
        return new String[]{p + "Au", p + "Av", p + "Bu", p + "Bv"};
    }

    static List<String> coordinateNames(int notes) {
        List<String> out = new ArrayList<>();
        for (int o = 1; o <= notes; o++) {
            for (int j = 0; j <= 1; j++) out.addAll(List.of(limbCoordinateNames(o, j)));
        }
        return out;
    }

    // ------------------------------------------------------------------ witness

    static Map<String, List<BigInteger>> witness(Fixture f, List<Note> outs) {
        Map<String, List<BigInteger>> w = new HashMap<>();
        put(w, "inU", f.input.commitment().affineU());
        put(w, "inV", f.input.commitment().affineV());
        put(w, "inAmount", BigInteger.valueOf(f.input.amount()));
        put(w, "inR", f.input.opening().blinding());
        put(w, "pkU", f.auditor.publicKey().affineU());
        put(w, "pkV", f.auditor.publicKey().affineV());
        if (f.shape == Shape.REDEEM) put(w, "price", BigInteger.valueOf(f.price));
        List<BigInteger> coordinates = new ArrayList<>();
        for (int o = 1; o <= outs.size(); o++) {
            Note n = outs.get(o - 1);
            put(w, "out" + o + "U", n.commitment().affineU());
            put(w, "out" + o + "V", n.commitment().affineV());
            put(w, "out" + o + "Amount", BigInteger.valueOf(n.amount()));
            put(w, "out" + o + "R", n.opening().blinding());
            for (int j = 0; j <= 1; j++) {
                Limb limb = n.limbs().get(j);
                put(w, "l" + o + j, limb.m());
                put(w, "k" + o + j, limb.k());
                String[] names = limbCoordinateNames(o, j);
                for (int q = 0; q < 4; q++) {
                    BigInteger c = limb.coordinates().get(q);
                    put(w, names[q], c);
                    if (f.layout == Layout.COMPRESSED) putBytes(w, names[q], i2osp32(c));
                }
                coordinates.addAll(limb.coordinates());
            }
        }
        if (f.layout == Layout.COMPRESSED) putDigest(w, serialize(coordinates));
        return w;
    }

    private static void putBytes(Map<String, List<BigInteger>> w, String name, byte[] be) {
        for (int k = 0; k < 32; k++) put(w, name + "_b" + k, BigInteger.valueOf(be[k] & 0xff));
    }

    private static void putDigest(Map<String, List<BigInteger>> w, byte[] bytes) {
        byte[] digest = Blake2bUtil.blake2bHash256(bytes);
        put(w, "digestHi", new BigInteger(1, Arrays.copyOfRange(digest, 0, 16)));
        put(w, "digestLo", new BigInteger(1, Arrays.copyOfRange(digest, 16, 32)));
    }

    /** Spec §8.3's serialization: {@code I2OSP(c, 32)} of every coordinate, in order. */
    static byte[] serialize(List<BigInteger> coordinates) {
        byte[] bytes = new byte[32 * coordinates.size()];
        for (int i = 0; i < coordinates.size(); i++) System.arraycopy(i2osp32(coordinates.get(i)), 0, bytes, 32 * i, 32);
        return bytes;
    }

    private static void put(Map<String, List<BigInteger>> w, String name, BigInteger value) {
        w.put(name, List.of(value));
    }

    // ------------------------------------------------------------------ tests

    @Test
    @DisplayName("Transfer, direct layout (spec §8.2): verifies; cost, mutations, invalid witnesses, reused randomness, recovery")
    void transferDirect() {
        Fixture f = new Fixture(Layout.DIRECT, Shape.TRANSFER, this);
        measureAndCheck(f);
        invalidWitnesses(f);
        reusedRandomnessRejected(f);
    }

    @Test
    @DisplayName("Redeem, direct layout (one change note and a public price): verifies; cost, mutations, recovery")
    void redeemDirect() {
        Fixture f = new Fixture(Layout.DIRECT, Shape.REDEEM, this);
        measureAndCheck(f);
        reusedRandomnessRejected(f);
    }

    @Test
    @Tag("heavy")
    @DisplayName("Transfer, hash-compressed layout (spec §8.3): verifies; cost, mutations, invalid witnesses, serialization binding")
    void transferCompressed() {
        Fixture f = new Fixture(Layout.COMPRESSED, Shape.TRANSFER, this);
        measureAndCheck(f);
        invalidWitnesses(f);
        compressedBinding(f);
    }

    private void measureAndCheck(Fixture f) {
        EvalResult honest = evaluate(f.program, context(f, f.outs, f.proof, Mutation.NONE));
        assertTrue(honest instanceof EvalResult.Success, "honest spend: " + honest);
        var budget = honest.budgetConsumed();
        System.out.printf("[D3a %s %s] constraints=%d publicInputs=%d prove=%d ms cpu=%d (%.1f%% of steps) mem=%d (%.1f%% of memory)%n",
                f.shape, f.layout, f.r1cs.constraints().size(), f.r1cs.numPublicInputs(), f.proveMillis,
                budget.cpuSteps(), 100.0 * budget.cpuSteps() / STEP_LIMIT,
                budget.memoryUnits(), 100.0 * budget.memoryUnits() / MEMORY_LIMIT);

        for (Mutation m : Mutation.values()) {
            if (m == Mutation.NONE || !m.appliesTo(f.shape)) continue;
            EvalResult r = evaluate(f.program, context(f, f.outs, f.proof, m));
            if (r instanceof EvalResult.Success) {
                throw new AssertionError(f.shape + " " + f.layout + ": mutation " + m + " was accepted");
            }
        }

        // Every created note, from the datum alone: the auditor decrypts the amount from the limbs
        // and opens its delivery; the owner opens its delivery.
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(TWO_32.longValueExact() - 1);
        NOfNKeyContext auditorContext = NOfNKeyContext.singleKey(f.auditor);
        for (Note n : f.outs) {
            List<BigInteger> audit = n.audit();
            long amount = 0;
            for (int j = 1; j >= 0; j--) {
                RawElGamalCiphertext raw = RawElGamalCiphertext.fromAffine(
                        audit.get(4 * j), audit.get(4 * j + 1), audit.get(4 * j + 2), audit.get(4 * j + 3));
                // Admitted on the strength of the spend proof just verified, which proves R_enc(32).
                ElGamalCiphertext ct = ElGamal.admit(raw, auditorContext, 32, statement -> true);
                amount = (amount << 32) | ElGamal.decryptWithSecret(ct, f.auditor, TWO_32.longValueExact() - 1, table);
            }
            assertEquals(n.amount(), amount, "the auditor recovers the amount from the limbs");
            BigInteger u = n.commitment().affineU();
            BigInteger v = n.commitment().affineV();
            NoteViewingKey owner = Arrays.equals(n.owner(), OWNER) ? f.ownerView : f.recipientView;
            assertEquals(n.opening().value(), NoteScanner.of(owner).open(n.deliveries().get(0), u, v).orElseThrow().value(),
                    "the owner opens its delivery");
            assertEquals(n.opening().value(), NoteScanner.of(f.auditorView).open(n.deliveries().get(1), u, v).orElseThrow().value(),
                    "the auditor opens its delivery");
        }
    }

    /** ADR-0055 I12: each invalid witness has no satisfying assignment, so no proof exists. */
    private static void invalidWitnesses(Fixture f) {
        Note out1 = f.outs.get(0);
        List<Limb> limbs = out1.limbs();
        // A wrong limb: the encryption is of L0 + 1, but the amount is unchanged.
        Note bumped = out1.withLimbs(List.of(Limb.of(limbs.get(0).m().add(BigInteger.ONE), limbs.get(0).k(), f.pk()), limbs.get(1)));
        assertNoWitness(f, bumped, "a limb that does not recombine to the amount");
        // A limb at 2^32 (L1 lowered to keep the sum): out of the 32-bit range.
        Note overflow = out1.withLimbs(List.of(
                Limb.of(limbs.get(0).m().add(TWO_32), limbs.get(0).k(), f.pk()),
                Limb.of(limbs.get(1).m().subtract(BigInteger.ONE), limbs.get(1).k(), f.pk())));
        assertNoWitness(f, overflow, "a limb at or above 2^32");
        assertNoWitness(f, out1.withLimbs(List.of(limbs.get(1), limbs.get(0))), "limb ciphertexts swapped");
        JubjubPoint stranger = ElGamalSecretKey.generate(RANDOM).publicKey().point();
        assertNoWitness(f, out1.withLimbs(List.of(Limb.of(limbs.get(0).m(), limbs.get(0).k(), stranger),
                Limb.of(limbs.get(1).m(), limbs.get(1).k(), stranger))), "ciphertexts under another key");
        BigInteger other = BigInteger.valueOf(out1.amount() + 1);
        assertNoWitness(f, out1.withLimbs(List.of(Limb.of(other.mod(TWO_32), limbs.get(0).k(), f.pk()),
                Limb.of(other.shiftRight(32), limbs.get(1).k(), f.pk()))), "limbs of a different amount");
    }

    private static void assertNoWitness(Fixture f, Note replacement, String what) {
        List<Note> outs = new ArrayList<>(f.outs);
        outs.set(0, replacement);
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(witness(f, outs), CurveId.BLS12_381), what);
    }

    private static void assertNoWitness(Fixture f, Map<String, List<BigInteger>> w, String what) {
        assertThrows(RuntimeException.class, () -> f.circuit.calculateWitness(w, CurveId.BLS12_381), what);
    }

    /**
     * D3a fresh randomness: a prover may reuse {@code k} across limbs (the circuit cannot forbid
     * it), which would make {@code L0 − L1} public. The proof verifies, so the validator refuses
     * equal handles.
     */
    private void reusedRandomnessRejected(Fixture f) {
        Note out1 = f.outs.get(0);
        BigInteger k = out1.limbs().get(0).k();
        Note reused = out1.withLimbs(List.of(out1.limbs().get(0), Limb.of(out1.limbs().get(1).m(), k, f.pk())));
        List<Note> outs = new ArrayList<>(f.outs);
        outs.set(0, reused);
        var proof = f.prove(witness(f, outs));
        assertTrue(evaluate(f.program, context(f, outs, proof, Mutation.NONE)) instanceof EvalResult.Failure,
                "one k for both limbs of a note is refused");
        if (f.shape == Shape.TRANSFER) {
            Note out2 = f.outs.get(1);
            Note across = out2.withLimbs(List.of(Limb.of(out2.limbs().get(0).m(), k, f.pk()), out2.limbs().get(1)));
            List<Note> outs2 = List.of(out1, across);
            var proof2 = f.prove(witness(f, outs2));
            assertTrue(evaluate(f.program, context(f, outs2, proof2, Mutation.NONE)) instanceof EvalResult.Failure,
                    "one k across two notes is refused");
        }
    }

    /**
     * The compressed layout's serialization binding (spec §8.3; ADR-0055 implementation note 7).
     * <ul>
     *   <li>Bytes that are not the coordinate (another ciphertext's, little-endian, a flipped
     *       digest half, swapped halves) have no witness.</li>
     *   <li>The bytes of {@code c + p} do have a witness (they equal {@code c} in the field), but
     *       hash to another digest: the proof verifies only against that digest, and the validator,
     *       which hashes the canonical datum coordinates, refuses it.</li>
     * </ul>
     */
    private void compressedBinding(Fixture f) {
        Map<String, List<BigInteger>> honest = witness(f, f.outs);
        List<String> names = coordinateNames(f.shape.outputs);
        String first = names.get(0);
        BigInteger c = honest.get(first).get(0);
        List<BigInteger> canonical = new ArrayList<>();
        for (String name : names) canonical.add(honest.get(name).get(0));

        // The R_enc coordinates are the real ciphertext's, but the hashed bytes are another
        // coordinate's (what a datum carrying unrelated audit data would hash).
        Map<String, List<BigInteger>> foreign = new HashMap<>(honest);
        BigInteger fake = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(BigInteger.valueOf(7)).normalized().affineU();
        List<BigInteger> fakeCoordinates = new ArrayList<>(canonical);
        fakeCoordinates.set(0, fake);
        putBytes(foreign, first, i2osp32(fake));
        putDigest(foreign, serialize(fakeCoordinates));
        assertNoWitness(f, foreign, "hashed bytes of another coordinate");

        Map<String, List<BigInteger>> littleEndian = new HashMap<>(honest);
        byte[] le = i2osp32(c);
        for (int i = 0; i < 16; i++) {
            byte t = le[i];
            le[i] = le[31 - i];
            le[31 - i] = t;
        }
        putBytes(littleEndian, first, le);
        assertNoWitness(f, littleEndian, "little-endian bytes");

        Map<String, List<BigInteger>> swapped = new HashMap<>(honest);
        swapped.put("digestHi", honest.get("digestLo"));
        swapped.put("digestLo", honest.get("digestHi"));
        assertNoWitness(f, swapped, "swapped digest halves");
        Map<String, List<BigInteger>> flippedHi = new HashMap<>(honest);
        flippedHi.put("digestHi", List.of(honest.get("digestHi").get(0).flipBit(0)));
        assertNoWitness(f, flippedHi, "a flipped bit in digest_hi");
        Map<String, List<BigInteger>> flippedLo = new HashMap<>(honest);
        flippedLo.put("digestLo", List.of(honest.get("digestLo").get(0).flipBit(127)));
        assertNoWitness(f, flippedLo, "a flipped bit in digest_lo");

        // c + p: a witness exists (equal to c in the field), but its digest is not the validator's.
        Map<String, List<BigInteger>> aliased = new HashMap<>(honest);
        byte[] bytes = serialize(canonical);
        System.arraycopy(i2osp32(c.add(P)), 0, bytes, 0, 32);
        putBytes(aliased, first, i2osp32(c.add(P)));
        putDigest(aliased, bytes);
        var aliasedProof = f.prove(aliased);
        assertTrue(evaluate(f.program, context(f, f.outs, aliasedProof, Mutation.NONE)) instanceof EvalResult.Failure,
                "the digest of a non-canonical serialization is refused against the canonical datum");
    }

    // ------------------------------------------------------------------ validator context

    enum Mutation {
        NONE,
        AUDIT_ABSENT, AUDIT_WRONG_OUT1, AUDIT_WRONG_OUT2, AUDIT_SWAPPED_BETWEEN_OUTPUTS, AUDIT_LIMBS_SWAPPED,
        AUDIT_NON_CANONICAL, AUDIT_SEVEN_ENTRIES,
        DELIVERY_SHORT, DELIVERY_MISSING,
        REGISTRY_MISSING, REGISTRY_OTHER_KEY, REGISTRY_WRONG_TOKEN, REGISTRY_SECOND_ENTRY_BEFORE, REGISTRY_SECOND_ENTRY_AFTER,
        REGISTRY_QUANTITY_TWO, REGISTRY_EXTRA_FIELD,
        PRICE_CHANGED, EXTRA_OUTPUT, MISSING_SIGNER, TAMPERED_PROOF;

        boolean appliesTo(Shape shape) {
            return switch (this) {
                case AUDIT_WRONG_OUT2, AUDIT_SWAPPED_BETWEEN_OUTPUTS -> shape == Shape.TRANSFER;
                default -> true;
            };
        }
    }

    private PlutusData context(Fixture f, List<Note> outs, SnarkjsToCardano.ProofCompressed proof, Mutation m) {
        TxOutRef ownRef = TestDataBuilder.randomTxOutRef_typed();
        PlutusData inDatum = noteDatum(f.input, f.input.audit(), f.input.deliveries());
        byte[] piA = m == Mutation.TAMPERED_PROOF ? flipped(proof.piA()) : proof.piA();
        long price = m == Mutation.PRICE_CHANGED ? f.price + 1 : f.price;
        PlutusData redeemer = PlutusData.constr(0, PlutusData.integer(BigInteger.valueOf(price)),
                PlutusData.bytes(piA), PlutusData.bytes(proof.piB()), PlutusData.bytes(proof.piC()));
        ScriptContextTestBuilder builder = spendingContext(ownRef, inDatum)
                .input(new TxInInfo(ownRef, txOut(SCRIPT_ADDRESS, NOTE_VALUE, inDatum)))
                .redeemer(redeemer);
        if (m != Mutation.MISSING_SIGNER) builder.signer(OWNER);

        List<List<BigInteger>> audits = new ArrayList<>();
        for (Note n : outs) audits.add(new ArrayList<>(n.audit()));
        switch (m) {
            case AUDIT_WRONG_OUT1 -> audits.get(0).set(5, audits.get(0).get(5).add(BigInteger.ONE));
            case AUDIT_WRONG_OUT2 -> audits.get(1).set(0, audits.get(1).get(0).add(BigInteger.ONE));
            case AUDIT_SWAPPED_BETWEEN_OUTPUTS -> {
                List<BigInteger> t = audits.get(0);
                audits.set(0, audits.get(1));
                audits.set(1, t);
            }
            case AUDIT_LIMBS_SWAPPED -> {
                List<BigInteger> a = audits.get(0);
                audits.set(0, concat(a.subList(4, 8), a.subList(0, 4)));
            }
            case AUDIT_NON_CANONICAL -> audits.get(0).set(2, audits.get(0).get(2).add(P));
            case AUDIT_SEVEN_ENTRIES -> audits.set(0, audits.get(0).subList(0, 7));
            default -> { }
        }
        for (int o = 0; o < outs.size(); o++) {
            Note n = outs.get(o);
            List<byte[]> deliveries = new ArrayList<>(n.deliveries());
            if (o == 0 && m == Mutation.DELIVERY_SHORT) deliveries.set(1, Arrays.copyOf(deliveries.get(1), 88));
            if (o == 0 && m == Mutation.DELIVERY_MISSING) deliveries.remove(1);
            PlutusData datum = o == 0 && m == Mutation.AUDIT_ABSENT
                    ? PlutusData.constr(0, PlutusData.bytes(n.owner()), PlutusData.integer(n.commitment().affineU()),
                            PlutusData.integer(n.commitment().affineV()), deliveriesData(deliveries))
                    : noteDatum(n, audits.get(o), deliveries);
            builder.output(txOut(SCRIPT_ADDRESS, NOTE_VALUE, datum));
        }
        if (m == Mutation.EXTRA_OUTPUT) builder.output(txOut(SCRIPT_ADDRESS, NOTE_VALUE,
                noteDatum(outs.get(0), outs.get(0).audit(), outs.get(0).deliveries())));

        if (m == Mutation.REGISTRY_SECOND_ENTRY_BEFORE) builder.referenceInput(retiredEntry());
        if (m != Mutation.REGISTRY_MISSING) {
            ElGamalPublicKey pk = m == Mutation.REGISTRY_OTHER_KEY ? ElGamalSecretKey.generate(RANDOM).publicKey() : f.auditor.publicKey();
            byte[] token = m == Mutation.REGISTRY_WRONG_TOKEN ? "auditor-2".getBytes() : REGISTRY_TOKEN;
            BigInteger quantity = m == Mutation.REGISTRY_QUANTITY_TWO ? BigInteger.TWO : BigInteger.ONE;
            PlutusData keyDatum = m == Mutation.REGISTRY_EXTRA_FIELD
                    ? PlutusData.constr(0, PlutusData.integer(pk.affineU()), PlutusData.integer(pk.affineV()), PlutusData.integer(BigInteger.ONE))
                    : PlutusData.constr(0, PlutusData.integer(pk.affineU()), PlutusData.integer(pk.affineV()));
            builder.referenceInput(registryEntry(token, quantity, keyDatum));
        }
        if (m == Mutation.REGISTRY_SECOND_ENTRY_AFTER) builder.referenceInput(retiredEntry());
        return builder.buildPlutusData();
    }

    /** A retired generation's entry for the same token: the submitter must not be able to choose. */
    private static TxInInfo retiredEntry() {
        ElGamalPublicKey retired = ElGamalSecretKey.generate(RANDOM).publicKey();
        return registryEntry(REGISTRY_TOKEN, BigInteger.ONE,
                PlutusData.constr(0, PlutusData.integer(retired.affineU()), PlutusData.integer(retired.affineV())));
    }

    private static TxInInfo registryEntry(byte[] token, BigInteger quantity, PlutusData keyDatum) {
        Value value = Value.lovelace(BigInteger.valueOf(2_000_000))
                .merge(Value.singleton(PolicyId.of(REGISTRY_POLICY), TokenName.of(token), quantity));
        return new TxInInfo(TestDataBuilder.randomTxOutRef_typed(), txOut(REGISTRY_ADDRESS, value, keyDatum));
    }

    private static PlutusData noteDatum(Note n, List<BigInteger> audit, List<byte[]> deliveries) {
        PlutusData[] entries = new PlutusData[audit.size()];
        for (int i = 0; i < audit.size(); i++) entries[i] = PlutusData.integer(audit.get(i));
        return PlutusData.constr(0,
                PlutusData.bytes(n.owner()),
                PlutusData.integer(n.commitment().affineU()),
                PlutusData.integer(n.commitment().affineV()),
                PlutusData.list(entries),
                deliveriesData(deliveries));
    }

    private static PlutusData deliveriesData(List<byte[]> deliveries) {
        PlutusData[] out = new PlutusData[deliveries.size()];
        for (int i = 0; i < deliveries.size(); i++) out[i] = PlutusData.bytes(deliveries.get(i));
        return PlutusData.list(out);
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
