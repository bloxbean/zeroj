package org.zeroj.examples.pedersen.g1;

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
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;
import org.zeroj.examples.pedersen.g1.onchain.G1BytesOpeningValidator;
import org.zeroj.examples.pedersen.g1.onchain.G1RunningTotalValidator;
import org.zeroj.examples.pedersen.g1.onchain.G1ScalarOpeningValidator;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M4: the three {@code pedersen-bls12-381-g1} example validators in the Julc VM.
 *
 * <p>Every honest case is built by the off-chain {@link G1Pedersen} API (pure Java), and the
 * running-total successor is cross-checked off-chain two ways ({@code withPublicDelta} against a
 * fresh {@code commitScalar} of the summed value), so the expected verdicts do not come from the
 * code under test. Every negative is a single mutation of an honest context, so a rejection is
 * attributable to that mutation.
 */
class G1PedersenOnChainTest extends ContractTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();
    private static final BigInteger Q = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final BigInteger TWO_64 = BigInteger.ONE.shiftLeft(64);

    private static final byte[] OWNER = filled(28, (byte) 0x0a);
    private static final byte[] OTHER = filled(28, (byte) 0x0b);
    private static final Address SCRIPT_ADDRESS = new Address(
            new Credential.ScriptCredential(ScriptHash.of(filled(28, (byte) 0x5c))), Optional.empty());
    /** Same script payment credential as {@link #SCRIPT_ADDRESS}, with a staking credential. */
    private static final Address STAKED_SCRIPT_ADDRESS = new Address(SCRIPT_ADDRESS.credential(),
            Optional.of(new StakingCredential.StakingHash(
                    new Credential.PubKeyCredential(PubKeyHash.of(filled(28, (byte) 0x5a))))));
    private static final Address OTHER_ADDRESS = new Address(
            new Credential.PubKeyCredential(PubKeyHash.of(OTHER)), Optional.empty());
    private static final Value LOCKED = Value.lovelace(BigInteger.valueOf(5_000_000));

    private static Program scalarProgram;
    private static Program totalProgram;
    private static Program bytesProgram;

    @BeforeAll
    static void compile() {
        G1PedersenOnChainTest compiler = new G1PedersenOnChainTest();
        scalarProgram = compiler.compileValidator(G1ScalarOpeningValidator.class, Path.of("src/test/java")).program();
        totalProgram = compiler.compileValidator(G1RunningTotalValidator.class, Path.of("src/test/java")).program();
        bytesProgram = compiler.compileValidator(G1BytesOpeningValidator.class, Path.of("src/test/java")).program();
    }

    // ==================================================================
    //  G1ScalarOpeningValidator
    // ==================================================================

    @Test
    @DisplayName("Scalar opening: honest openings (incl. 2^64 − 1 and the identity) are accepted")
    void scalarHonest() {
        BigInteger r = random();
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(1_000_000), r);
        assertTrue(PEDERSEN.verifyScalar(c, BigInteger.valueOf(1_000_000), r), "off-chain oracle");
        EvalResult ok = scalar(OWNER, c.toPointBytes(), BigInteger.valueOf(1_000_000), r, true);
        assertSuccess(ok);
        System.out.println("[G1ScalarOpeningValidator] honest opening budget: " + ok.budgetConsumed());

        BigInteger max = TWO_64.subtract(BigInteger.ONE);
        BigInteger r2 = random();
        assertSuccess(scalar(OWNER, PEDERSEN.commitScalar(max, r2).toPointBytes(), max, r2, true));
        BigInteger r3 = random();
        assertSuccess(scalar(OWNER, PEDERSEN.commitScalar(BigInteger.ZERO, r3).toPointBytes(), BigInteger.ZERO, r3, true));
        byte[] identity = PEDERSEN.commitScalar(BigInteger.ZERO, BigInteger.ZERO).toPointBytes();
        assertArrayEquals(HEX.parseHex("c0" + "00".repeat(47)), identity, "C(0, 0) is the identity");
        assertSuccess(scalar(OWNER, identity, BigInteger.ZERO, BigInteger.ZERO, true));
    }

    @Test
    @DisplayName("Scalar opening: wrong value, wrong blinding, missing signer and a malformed owner are rejected")
    void scalarWrongOpeningOrSigner() {
        BigInteger m = BigInteger.valueOf(1_000_000);
        BigInteger r = random();
        byte[] c = PEDERSEN.commitScalar(m, r).toPointBytes();
        assertRejected(scalar(OWNER, c, m.add(BigInteger.ONE), r, true));
        assertRejected(scalar(OWNER, c, m.subtract(BigInteger.ONE), r, true));
        assertRejected(scalar(OWNER, c, m, r.add(BigInteger.ONE).mod(Q), true));
        assertRejected(scalar(OWNER, c, r.mod(TWO_64), m, true));
        assertRejected(scalar(OWNER, c, m, r, false));
        byte[] longOwner = Arrays.copyOf(OWNER, 29);
        assertRejected(scalar(longOwner, c, m, r, true));
    }

    @Test
    @DisplayName("Scalar opening: values ≥ 2^64 are refused even though the opening is algebraically valid")
    void scalarAmountBound() {
        for (BigInteger m : new BigInteger[] {TWO_64, TWO_64.add(BigInteger.ONE), Q.subtract(BigInteger.ONE)}) {
            BigInteger r = random();
            G1PedersenCommitment c = PEDERSEN.commitScalar(m, r);
            assertTrue(PEDERSEN.verifyScalar(c, m, r), "the unbounded off-chain opening holds for m = " + m);
            assertRejected(scalar(OWNER, c.toPointBytes(), m, r, true));
        }
    }

    @Test
    @DisplayName("Scalar opening: out-of-range and aliased scalars (q, −1, r + q) are refused")
    void scalarNonCanonicalScalars() {
        BigInteger m = BigInteger.valueOf(42);
        BigInteger r = random();
        byte[] c = PEDERSEN.commitScalar(m, r).toPointBytes();
        assertRejected(scalar(OWNER, c, m, Q, true));
        assertRejected(scalar(OWNER, c, m, BigInteger.ONE.negate(), true));
        assertRejected(scalar(OWNER, c, m, r.add(Q), true), "r + q opens the same point but must be refused");
        assertRejected(scalar(OWNER, c, m, r.subtract(Q), true), "r − q is negative");
        assertRejected(scalar(OWNER, c, BigInteger.ONE.negate(), r, true));
        assertRejected(scalar(OWNER, c, Q, r, true));
    }

    @Test
    @DisplayName("Scalar opening: malformed, non-canonical and non-subgroup commitments are rejected")
    void scalarMalformedCommitments() {
        BigInteger m = BigInteger.valueOf(7);
        BigInteger r = random();
        byte[] c = PEDERSEN.commitScalar(m, r).toPointBytes();
        assertSuccess(scalar(OWNER, c, m, r, true));
        for (Map.Entry<String, byte[]> bad : malformedCommitments(c).entrySet()) {
            assertRejected(scalar(OWNER, bad.getValue(), m, r, true), bad.getKey());
        }
    }

    // ==================================================================
    //  G1RunningTotalValidator
    // ==================================================================

    @Test
    @DisplayName("Running total: honest updates (+250, −100, 0, ±(2^64 − 1)) are accepted")
    void totalHonest() {
        BigInteger start = BigInteger.valueOf(1_000);
        BigInteger r = random();
        G1PedersenCommitment c = PEDERSEN.commitScalar(start, r);
        BigInteger max = TWO_64.subtract(BigInteger.ONE);
        for (BigInteger delta : new BigInteger[] {BigInteger.valueOf(250), BigInteger.valueOf(-100),
                BigInteger.ZERO, max, max.negate()}) {
            G1PedersenCommitment next = c.withPublicDelta(delta, 64);
            // Independent off-chain cross-check: the same point from a fresh commitment to m + δ mod q.
            assertEquals(PEDERSEN.commitScalar(start.add(delta).mod(Q), r), next, "oracle for δ = " + delta);
            EvalResult ok = total(totalDatum(OWNER, c.toPointBytes()), delta,
                    List.of(scriptOutput(totalDatum(OWNER, next.toPointBytes()))), List.of(), true);
            assertSuccess(ok);
            if (delta.equals(BigInteger.valueOf(250))) {
                System.out.println("[G1RunningTotalValidator] honest +250 update budget: " + ok.budgetConsumed());
            }
        }
    }

    @Test
    @DisplayName("Running total: wrong delta, wrong or substituted next commitment and a non-canonical successor are rejected")
    void totalWrongCommitment() {
        BigInteger r = random();
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(1_000), r);
        PlutusData in = totalDatum(OWNER, c.toPointBytes());
        BigInteger delta = BigInteger.valueOf(250);
        byte[] honestNext = c.withPublicDelta(delta, 64).toPointBytes();
        assertSuccess(total(in, delta, List.of(scriptOutput(totalDatum(OWNER, honestNext))), List.of(), true));

        Map<String, byte[]> wrongNext = new LinkedHashMap<>();
        wrongNext.put("next = C + 251", c.withPublicDelta(BigInteger.valueOf(251), 64).toPointBytes());
        wrongNext.put("next = C − 250", c.withPublicDelta(delta.negate(), 64).toPointBytes());
        wrongNext.put("next = C (unchanged)", c.toPointBytes());
        wrongNext.put("next = C(1250, fresh r)", PEDERSEN.commitScalar(BigInteger.valueOf(1_250), random()).toPointBytes());
        wrongNext.put("next negated (sort flag flipped)", flipBits(honestNext, 0, 0x20));
        for (Map.Entry<String, byte[]> e : wrongNext.entrySet()) {
            assertRejected(total(in, delta, List.of(scriptOutput(totalDatum(OWNER, e.getValue()))), List.of(), true),
                    e.getKey());
        }
        assertRejected(total(in, BigInteger.valueOf(251), List.of(scriptOutput(totalDatum(OWNER, honestNext))),
                List.of(), true), "redeemer delta 251 with a +250 successor");
        assertRejected(total(in, delta.negate(), List.of(scriptOutput(totalDatum(OWNER, honestNext))),
                List.of(), true), "redeemer delta −250 with a +250 successor");
    }

    @Test
    @DisplayName("Running total: |delta| ≥ 2^64 is refused even with the algebraically correct successor")
    void totalDeltaBound() {
        BigInteger r = random();
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(1_000), r);
        PlutusData in = totalDatum(OWNER, c.toPointBytes());
        assertThrows(IllegalArgumentException.class, () -> c.withPublicDelta(TWO_64, 64), "off-chain rule");
        G1PedersenCommitment step = PEDERSEN.commitScalar(TWO_64, BigInteger.ZERO);
        byte[] up = c.add(step).toPointBytes();
        byte[] down = c.subtract(step).toPointBytes();
        assertRejected(total(in, TWO_64, List.of(scriptOutput(totalDatum(OWNER, up))), List.of(), true), "+2^64");
        assertRejected(total(in, TWO_64.negate(), List.of(scriptOutput(totalDatum(OWNER, down))), List.of(), true),
                "−2^64");
        G1PedersenCommitment bigStep = PEDERSEN.commitScalar(TWO_64.add(BigInteger.ONE), BigInteger.ZERO);
        assertRejected(total(in, TWO_64.add(BigInteger.ONE).negate(),
                List.of(scriptOutput(totalDatum(OWNER, c.subtract(bigStep).toPointBytes()))), List.of(), true),
                "−(2^64 + 1)");
    }

    @Test
    @DisplayName("Running total: missing, duplicated, relocated and non-inline continuing outputs are rejected")
    void totalContinuingOutputShape() {
        BigInteger r = random();
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(1_000), r);
        PlutusData in = totalDatum(OWNER, c.toPointBytes());
        BigInteger delta = BigInteger.valueOf(250);
        byte[] next = c.withPublicDelta(delta, 64).toPointBytes();
        PlutusData nextDatum = totalDatum(OWNER, next);

        Map<String, List<TxOut>> cases = new LinkedHashMap<>();
        cases.put("no continuing output", List.of(
                new TxOut(OTHER_ADDRESS, LOCKED, new OutputDatum.OutputDatumInline(nextDatum), Optional.empty())));
        cases.put("no outputs at all", List.of());
        cases.put("two continuing outputs", List.of(scriptOutput(nextDatum), scriptOutput(nextDatum)));
        cases.put("continuing output under another staking credential", List.of(
                new TxOut(STAKED_SCRIPT_ADDRESS, LOCKED, new OutputDatum.OutputDatumInline(nextDatum), Optional.empty())));
        cases.put("honest output plus a second one under another staking credential", List.of(scriptOutput(nextDatum),
                new TxOut(STAKED_SCRIPT_ADDRESS, LOCKED, new OutputDatum.OutputDatumInline(nextDatum), Optional.empty())));
        cases.put("datum hash instead of inline datum", List.of(new TxOut(SCRIPT_ADDRESS, LOCKED,
                new OutputDatum.OutputDatumHash(DatumHash.of(filled(32, (byte) 0x33))), Optional.empty())));
        cases.put("no datum", List.of(new TxOut(SCRIPT_ADDRESS, LOCKED, new OutputDatum.NoOutputDatum(), Optional.empty())));
        cases.put("changed owner", List.of(scriptOutput(totalDatum(OTHER, next))));
        cases.put("owner of 27 octets", List.of(scriptOutput(totalDatum(Arrays.copyOf(OWNER, 27), next))));
        cases.put("commitment of 49 octets", List.of(scriptOutput(totalDatum(OWNER, Arrays.copyOf(next, 49)))));
        cases.put("commitment of 47 octets", List.of(scriptOutput(totalDatum(OWNER, Arrays.copyOf(next, 47)))));
        cases.put("extra datum field", List.of(scriptOutput(PlutusData.constr(0,
                PlutusData.bytes(OWNER), PlutusData.bytes(next), PlutusData.integer(BigInteger.ONE)))));
        cases.put("constructor tag 1", List.of(scriptOutput(PlutusData.constr(1,
                PlutusData.bytes(OWNER), PlutusData.bytes(next)))));
        cases.put("commitment as an integer", List.of(scriptOutput(PlutusData.constr(0,
                PlutusData.bytes(OWNER), PlutusData.integer(new BigInteger(1, next))))));
        for (Map.Entry<String, List<TxOut>> e : cases.entrySet()) {
            assertRejected(total(in, delta, e.getValue(), List.of(), true), e.getKey());
        }
    }

    @Test
    @DisplayName("Running total: a second script input, a missing signer and a malformed consumed commitment are rejected")
    void totalInputsAndSigner() {
        BigInteger r = random();
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(1_000), r);
        PlutusData in = totalDatum(OWNER, c.toPointBytes());
        BigInteger delta = BigInteger.valueOf(250);
        List<TxOut> honestOut = List.of(scriptOutput(totalDatum(OWNER, c.withPublicDelta(delta, 64).toPointBytes())));
        PlutusData otherTotal = totalDatum(OWNER, PEDERSEN.commitScalar(BigInteger.valueOf(5), random()).toPointBytes());

        assertRejected(total(in, delta, honestOut, List.of(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                scriptOutput(otherTotal))), true), "second script input");
        assertRejected(total(in, delta, honestOut, List.of(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                new TxOut(STAKED_SCRIPT_ADDRESS, LOCKED, new OutputDatum.OutputDatumInline(otherTotal),
                        Optional.empty()))), true), "second script input under another staking credential");
        assertSuccess(total(in, delta, honestOut, List.of(new TxInInfo(TestDataBuilder.randomTxOutRef_typed(),
                new TxOut(OTHER_ADDRESS, LOCKED, new OutputDatum.NoOutputDatum(), Optional.empty()))), true));
        assertRejected(total(in, delta, honestOut, List.of(), false), "missing signer");

        for (Map.Entry<String, byte[]> bad : malformedCommitments(c.toPointBytes()).entrySet()) {
            assertRejected(total(totalDatum(OWNER, bad.getValue()), delta, honestOut, List.of(), true),
                    "consumed commitment: " + bad.getKey());
        }
    }

    // ==================================================================
    //  G1BytesOpeningValidator
    // ==================================================================

    @Test
    @DisplayName("Bytes opening: honest openings (0, 1, 300 octets) are accepted")
    void bytesHonest() {
        for (int n : new int[] {0, 1, 300}) {
            byte[] payload = pattern(n);
            BigInteger r = random();
            G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
            assertTrue(PEDERSEN.verifyBytes(c, payload, r), "off-chain oracle");
            EvalResult ok = bytes(OWNER, c.toPointBytes(), payload, r, true);
            assertSuccess(ok);
            System.out.println("[G1BytesOpeningValidator] honest " + n + "-octet opening budget: " + ok.budgetConsumed());
        }
    }

    @Test
    @DisplayName("Bytes opening: a flipped, dropped or appended octet, a wrong blinding and a missing signer are rejected")
    void bytesTampered() {
        byte[] payload = pattern(300);
        BigInteger r = random();
        byte[] c = PEDERSEN.commitBytes(payload, r).toPointBytes();
        for (int index : new int[] {0, 150, 299}) {
            assertRejected(bytes(OWNER, c, flipBits(payload, index, 0x01), r, true), "flipped octet " + index);
        }
        assertRejected(bytes(OWNER, c, Arrays.copyOf(payload, 299), r, true), "dropped last octet");
        assertRejected(bytes(OWNER, c, Arrays.copyOf(payload, 301), r, true), "appended zero octet");
        assertRejected(bytes(OWNER, c, Arrays.copyOfRange(payload, 1, 300), r, true), "dropped first octet");
        assertRejected(bytes(OWNER, c, payload, r.add(BigInteger.ONE).mod(Q), true), "wrong blinding");
        assertRejected(bytes(OWNER, c, payload, r, false), "missing signer");
        assertRejected(bytes(Arrays.copyOf(OWNER, 29), c, payload, r, true), "owner of 29 octets");
    }

    @Test
    @DisplayName("Bytes opening: out-of-range and aliased blindings and malformed commitments are rejected")
    void bytesNonCanonical() {
        byte[] payload = pattern(64);
        BigInteger r = random();
        byte[] c = PEDERSEN.commitBytes(payload, r).toPointBytes();
        assertSuccess(bytes(OWNER, c, payload, r, true));
        assertRejected(bytes(OWNER, c, payload, Q, true), "r = q");
        assertRejected(bytes(OWNER, c, payload, BigInteger.ONE.negate(), true), "r = −1");
        assertRejected(bytes(OWNER, c, payload, r.add(Q), true), "r + q aliases the same point but must be refused");
        for (Map.Entry<String, byte[]> bad : malformedCommitments(c).entrySet()) {
            assertRejected(bytes(OWNER, bad.getValue(), payload, r, true), bad.getKey());
        }
    }

    // ==================================================================
    //  Harness
    // ==================================================================

    /** Malformed variants of a valid finite commitment {@code c}: each must fail decoding or opening. */
    private static Map<String, byte[]> malformedCommitments(byte[] c) {
        Map<String, byte[]> m = new LinkedHashMap<>();
        m.put("sort flag flipped (a different, valid point)", flipBits(c, 0, 0x20));
        m.put("compression flag cleared", flipBits(c, 0, 0x80));
        m.put("infinity flag set", flipBits(c, 0, 0x40));
        m.put("80 ‖ 0^47 (x = 0, order 3)", HEX.parseHex("80" + "00".repeat(47)));
        m.put("a0 ‖ 0^47 (x = 0, sort flag, order 3)", HEX.parseHex("a0" + "00".repeat(47)));
        m.put("80 ‖ 0^46 ‖ 04 (on the curve, not in G1)", HEX.parseHex("80" + "00".repeat(46) + "04"));
        m.put("80 ‖ 0^46 ‖ 01 (not on the curve)", HEX.parseHex("80" + "00".repeat(46) + "01"));
        m.put("e0 ‖ 0^47 (infinity with the sort flag)", HEX.parseHex("e0" + "00".repeat(47)));
        m.put("c0 ‖ 0^46 ‖ 01 (infinity with a coordinate bit)", HEX.parseHex("c0" + "00".repeat(46) + "01"));
        m.put("G + (0, 2), mixed order", HEX.parseHex(
                "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4"));
        m.put("x = P_381", HEX.parseHex(
                "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"));
        m.put("47 octets", Arrays.copyOf(c, 47));
        m.put("49 octets", Arrays.copyOf(c, 49));
        m.put("96 octets", Arrays.copyOf(c, 96));
        m.put("empty", new byte[0]);
        return m;
    }

    private EvalResult scalar(byte[] owner, byte[] commitment, BigInteger value, BigInteger blinding, boolean signed) {
        PlutusData datum = holdingDatum(owner, commitment);
        PlutusData redeemer = PlutusData.constr(0, PlutusData.integer(value), PlutusData.integer(blinding));
        return evaluate(scalarProgram, simpleSpend(datum, redeemer, signed));
    }

    private EvalResult bytes(byte[] owner, byte[] commitment, byte[] payload, BigInteger blinding, boolean signed) {
        PlutusData datum = holdingDatum(owner, commitment);
        PlutusData redeemer = PlutusData.constr(0, PlutusData.bytes(payload), PlutusData.integer(blinding));
        return evaluate(bytesProgram, simpleSpend(datum, redeemer, signed));
    }

    /** One script input carrying {@code datum}, its value paid to another address. */
    private PlutusData simpleSpend(PlutusData datum, PlutusData redeemer, boolean signed) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        ScriptContextTestBuilder builder = spendingContext(ref, datum)
                .input(new TxInInfo(ref, scriptOutput(datum)))
                .output(new TxOut(OTHER_ADDRESS, LOCKED, new OutputDatum.NoOutputDatum(), Optional.empty()))
                .redeemer(redeemer);
        builder.signer(signed ? OWNER : OTHER);
        return builder.buildPlutusData();
    }

    private EvalResult total(PlutusData inputDatum, BigInteger delta, List<TxOut> outputs,
                             List<TxInInfo> extraInputs, boolean signed) {
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        ScriptContextTestBuilder builder = spendingContext(ref, inputDatum)
                .input(new TxInInfo(ref, scriptOutput(inputDatum)))
                .redeemer(PlutusData.constr(0, PlutusData.integer(delta)));
        for (TxInInfo extra : extraInputs) builder.input(extra);
        for (TxOut out : outputs) builder.output(out);
        builder.signer(signed ? OWNER : OTHER);
        return evaluate(totalProgram, builder.buildPlutusData());
    }

    private static PlutusData holdingDatum(byte[] owner, byte[] commitment) {
        return PlutusData.constr(0, PlutusData.bytes(owner), PlutusData.bytes(commitment));
    }

    private static PlutusData totalDatum(byte[] owner, byte[] commitment) {
        return holdingDatum(owner, commitment);
    }

    private static TxOut scriptOutput(PlutusData datum) {
        return new TxOut(SCRIPT_ADDRESS, LOCKED, new OutputDatum.OutputDatumInline(datum), Optional.empty());
    }

    private static void assertRejected(EvalResult result) {
        assertRejected(result, "mutation");
    }

    private static void assertRejected(EvalResult result, String label) {
        assertFalse(result.isSuccess(), label + ": must be rejected");
    }

    private static byte[] flipBits(byte[] bytes, int index, int mask) {
        byte[] copy = bytes.clone();
        copy[index] ^= (byte) mask;
        return copy;
    }

    static BigInteger random() {
        return G1Pedersen.randomBlinding(RANDOM);
    }

    /** Pattern payload of {@code commitment-profiles-v1} §13.2: octet {@code i} is {@code (131·i + 17) mod 256}. */
    static byte[] pattern(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (131 * i + 17);
        }
        return b;
    }

    static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        Arrays.fill(out, value);
        return out;
    }
}
