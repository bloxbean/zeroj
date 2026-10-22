package org.zeroj.onchain.julc.pedersen;

import org.julclang.compiler.CompileResult;
import org.julclang.core.DefaultFun;
import org.julclang.core.PlutusData;
import org.julclang.ledger.TxOutRef;
import org.julclang.testkit.ContractTest;
import org.julclang.testkit.TestDataBuilder;
import org.julclang.vm.EvalResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M4: {@code PedersenG1Lib} in the Julc VM against the off-chain {@link G1Pedersen} and the
 * pinned values of {@code pedersen-bls12-381-g1-v1} §2.2, §10.
 *
 * <p>Every rejection by a library guard is shown to happen before the builtin it protects, by exact
 * builtin counts over the whole evaluation ({@link MarkedBuiltinCounts}): a refused scalar, width or
 * delta runs no {@code bls12_381_G1_scalarMul} or {@code multiScalarMul}, and a refused length runs no
 * {@code bls12_381_G1_uncompress} beyond the pinned bases.
 */
class PedersenG1LibVmTest extends ContractTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final BigInteger Q = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final String G_HEX =
            "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String H_HEX =
            "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";
    private static final String IDENTITY_HEX = "c0" + "00".repeat(47);
    private static final byte[] DST_B =
            "ZeroJ-pedersen-bls12-381-g1-basis-v1-BLS12381G1_XMD:SHA-256_SSWU_RO_".getBytes(StandardCharsets.US_ASCII);

    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();
    private final Map<Class<?>, CompileResult> compiled = new HashMap<>();
    /** Builtin counts of the most recent {@link #run}, from the marked cost model. */
    private MarkedBuiltinCounts.Counts lastCounts;

    // ------------------------------------------------------------------ bases

    @Test
    @DisplayName("I1: bls12_381_G1_hashToGroup(\"G\"/\"H\", DST_B) reproduces the pinned bases on-chain")
    void basesReproduce() {
        EvalResult ok = run(PedersenG1BasesProbe.class, PlutusData.bytes(DST_B));
        assertSuccess(ok);
        System.out.println("[PedersenG1Lib] hashToGroup base reproduction budget: " + ok.budgetConsumed());
        byte[] otherTag = DST_B.clone();
        otherTag[0] ^= 1;
        assertFailure(run(PedersenG1BasesProbe.class, PlutusData.bytes(otherTag)));
    }

    // ------------------------------------------------------------------ decoding

    @Test
    @DisplayName("Decoding accepts the bases, the identity and generated commitments, and re-encodes them exactly")
    void decodeAccepts() {
        for (String hex : List.of(G_HEX, H_HEX, IDENTITY_HEX)) {
            assertSuccess(run(PedersenG1DecodeProbe.class, PlutusData.bytes(HEX.parseHex(hex))));
        }
        for (int i = 0; i < 4; i++) {
            G1PedersenCommitment c = PEDERSEN.commitScalar(random(), random());
            assertSuccess(run(PedersenG1DecodeProbe.class, PlutusData.bytes(c.toPointBytes())));
        }
    }

    @Test
    @DisplayName("Decoding rejects every spec §10.4 negative; a wrong length never reaches uncompress")
    void decodeRejects() {
        List<String> negatives = List.of(
                "e0" + "00".repeat(47),                  // infinity with the sort flag
                "c0" + "00".repeat(46) + "01",           // infinity with a coordinate bit
                "80" + "00".repeat(47),                  // x = 0: order 3
                "a0" + "00".repeat(47),                  // x = 0, sort flag: order 3
                "00" + G_HEX.substring(2),               // compression flag clear
                "80" + "00".repeat(46) + "01",           // x = 1: not on the curve
                "80" + "00".repeat(46) + "04",           // x = 4: on the curve, not in G1
                "b6ee2defa35097e6bbaea5ab251479b37157dedfcbc4b319181bf28298f048a66eb93dc0230190c18ae135644c2d3df4",
                "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab");
        for (String hex : negatives) {
            assertFailure(run(PedersenG1DecodeProbe.class, PlutusData.bytes(HEX.parseHex(hex))));
        }
        for (int length : new int[] {0, 47, 49, 96}) {
            EvalResult r = run(PedersenG1DecodeProbe.class, PlutusData.bytes(new byte[length]));
            assertFailure(r);
            assertEquals(0, lastCounts.uncompress(), "length " + length + ": refused before uncompress");
        }
        byte[] longer = new byte[49];
        System.arraycopy(HEX.parseHex(G_HEX), 0, longer, 0, 48);
        assertFailure(run(PedersenG1DecodeProbe.class, PlutusData.bytes(longer)));
        assertEquals(0, lastCounts.uncompress(), "G with a trailing octet");
        assertSuccess(run(PedersenG1DecodeProbe.class, PlutusData.bytes(HEX.parseHex(G_HEX))));
        assertEquals(1, lastCounts.uncompress(), "control: an accepted decode runs exactly one uncompress");
    }

    // ------------------------------------------------------------------ scalar openings

    @Test
    @DisplayName("Scalar openings: spec §10.3 values verify; wrong openings fail")
    void scalarOpenings() {
        BigInteger qm1 = Q.subtract(BigInteger.ONE);
        assertOpening(IDENTITY_HEX, BigInteger.ZERO, BigInteger.ZERO, true);
        assertOpening(G_HEX, BigInteger.ONE, BigInteger.ZERO, true);
        assertOpening(H_HEX, BigInteger.ZERO, BigInteger.ONE, true);
        assertOpening("830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650",
                qm1, qm1, true);
        String c12345 = "8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352cddecd632d2b758fc4";
        EvalResult ok = opening(c12345, BigInteger.valueOf(12345), BigInteger.valueOf(67890), BigInteger.ZERO);
        assertSuccess(ok);
        System.out.println("[PedersenG1Lib] scalar opening budget: " + ok.budgetConsumed());
        assertOpening(c12345, BigInteger.valueOf(12346), BigInteger.valueOf(67890), false);
        assertOpening(c12345, BigInteger.valueOf(12345), BigInteger.valueOf(67891), false);
        assertOpening(G_HEX, BigInteger.ZERO, BigInteger.ONE, false);
        for (int i = 0; i < 3; i++) {
            BigInteger m = random();
            BigInteger r = random();
            String c = HEX.formatHex(PEDERSEN.commitScalar(m, r).toPointBytes());
            assertOpening(c, m, r, true);
            assertOpening(c, m.add(BigInteger.ONE).mod(Q), r, false);
        }
    }

    @Test
    @DisplayName("Check 1 and check 2 fail the script before any scalarMul")
    void scalarGuards() {
        BigInteger[] bad = {Q, Q.add(BigInteger.ONE), BigInteger.ONE.negate(), Q.negate()};
        for (BigInteger x : bad) {
            assertRefusedBeforeScalarMul(opening(G_HEX, x, BigInteger.ZERO, BigInteger.ZERO), "m = " + x);
            assertRefusedBeforeScalarMul(opening(G_HEX, BigInteger.ONE, x, BigInteger.ZERO), "r = " + x);
        }
        BigInteger qm1 = Q.subtract(BigInteger.ONE);
        String cMax = "830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650";
        // q − 1 ≥ 2^254: check 2 at the widest width still refuses it, before any multiplication.
        assertSuccess(opening(cMax, qm1, qm1, BigInteger.ZERO));
        assertRefusedBeforeScalarMul(opening(cMax, qm1, qm1, BigInteger.valueOf(254)), "m = q − 1, k = 254");
        for (int k : new int[] {1, 64, 252, 253, 254}) {
            BigInteger below = BigInteger.ONE.shiftLeft(k).subtract(BigInteger.ONE);
            BigInteger r = random();
            String ok = HEX.formatHex(PEDERSEN.commitScalar(below, r).toPointBytes());
            assertSuccess(opening(ok, below, r, BigInteger.valueOf(k)));
            BigInteger at = BigInteger.ONE.shiftLeft(k);
            if (at.compareTo(Q) < 0) {
                String c = HEX.formatHex(PEDERSEN.commitScalar(at, r).toPointBytes());
                assertRefusedBeforeScalarMul(opening(c, at, r, BigInteger.valueOf(k)), "m = 2^" + k);
            }
        }
        for (long k : new long[] {-1, 255, 256}) {
            assertRefusedBeforeScalarMul(opening(G_HEX, BigInteger.ONE, BigInteger.ZERO, BigInteger.valueOf(k)),
                    "amountBits " + k);
        }
    }

    // ------------------------------------------------------------------ bytes

    @Test
    @DisplayName("HashBytesToScalarG1 on-chain equals the spec §10.2 values")
    void hashToScalar() {
        String[][] cases = {
                {"0", "36315447437668222813564192209050807153821375512821708312164585800119004767398"},
                {"1", "17446826573447758279414620354847772216162392386874241427805739007456445167270"},
                {"55", "4769885727161205208895793752532058125538937305946508790125793345496789763442"},
                {"56", "44447803342360626358699221713325796379764762051949152351159963802212607565535"},
                {"64", "21158407019535989839516034496492483749423603674815396635618901986493989358291"},
                {"129", "10636700515201835153547363743684853122590858874478588016559740395075199699391"},
                {"1024", "51032631804351372587695208740820262018544153677477339797817422801122177762967"},
        };
        for (String[] c : cases) {
            byte[] payload = pattern(Integer.parseInt(c[0]));
            assertSuccess(run(PedersenG1HashProbe.class, PlutusData.bytes(payload), PlutusData.integer(new BigInteger(c[1]))));
            assertFailure(run(PedersenG1HashProbe.class, PlutusData.bytes(payload),
                    PlutusData.integer(new BigInteger(c[1]).add(BigInteger.ONE))));
        }
        assertSuccess(run(PedersenG1HashProbe.class, PlutusData.bytes("abc".getBytes(StandardCharsets.US_ASCII)),
                PlutusData.integer(new BigInteger("425016933681726855004915202875618514367841089254790273686098534787449164925"))));
    }

    @Test
    @DisplayName("Byte openings verify; a changed payload, blinding or commitment fails; r ≥ q is refused before hashing")
    void bytesOpenings() {
        for (int n : new int[] {0, 1, 56, 200, 1024}) {
            byte[] payload = pattern(n);
            BigInteger r = random();
            G1PedersenBytesCommitment c = PEDERSEN.commitBytes(payload, r);
            EvalResult ok = bytesOpening(c.toPointBytes(), payload, r);
            assertSuccess(ok);
            System.out.println("[PedersenG1Lib] bytes opening, " + n + " octets, budget: " + ok.budgetConsumed());
            if (n > 0) {
                byte[] flipped = payload.clone();
                flipped[n / 2] ^= 1;
                assertFailure(bytesOpening(c.toPointBytes(), flipped, r));
                assertFailure(bytesOpening(c.toPointBytes(), Arrays.copyOf(payload, n - 1), r));
            }
            byte[] extended = Arrays.copyOf(payload, n + 1);
            assertFailure(bytesOpening(c.toPointBytes(), extended, r));
            assertFailure(bytesOpening(c.toPointBytes(), payload, r.add(BigInteger.ONE).mod(Q)));
        }
        G1PedersenBytesCommitment c = PEDERSEN.commitBytes(pattern(10), BigInteger.ONE);
        for (BigInteger bad : new BigInteger[] {Q, BigInteger.ONE.negate()}) {
            assertRefusedBeforeScalarMul(bytesOpening(c.toPointBytes(), pattern(10), bad), "r = " + bad);
        }
    }

    // ------------------------------------------------------------------ delta and sums

    @Test
    @DisplayName("Public deltas match the off-chain withPublicDelta; out-of-bound deltas and widths are refused before scalarMul")
    void deltas() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(1000), random());
        for (int k : new int[] {1, 64, 253}) {
            BigInteger max = BigInteger.ONE.shiftLeft(k).subtract(BigInteger.ONE);
            for (BigInteger delta : new BigInteger[] {max, max.negate(), BigInteger.ZERO}) {
                byte[] expected = c.withPublicDelta(delta, k).toPointBytes();
                EvalResult ok = delta(c.toPointBytes(), delta, k, expected);
                assertSuccess(ok);
            }
            BigInteger at = BigInteger.ONE.shiftLeft(k);
            assertRefusedBeforeScalarMul(delta(c.toPointBytes(), at, k, c.toPointBytes()), "+2^" + k);
            assertRefusedBeforeScalarMul(delta(c.toPointBytes(), at.negate(), k, c.toPointBytes()), "-2^" + k);
        }
        EvalResult measured = delta(c.toPointBytes(), BigInteger.valueOf(-250), 64,
                c.withPublicDelta(BigInteger.valueOf(-250), 64).toPointBytes());
        assertSuccess(measured);
        assertEquals(new MarkedBuiltinCounts.Counts(2, 1, 0), lastCounts,
                "a delta: the commitment and G decompressed, and the single multiplication [|δ|]·G");
        // I3: a negative delta is applied as [|δ|]·G negated; scalarMul only ever sees |δ| (the trace
        // keeps the last 20 builtins, which include this multiplication).
        List<String> scalarArgs = measured.builtinTrace().stream()
                .filter(e -> e.fun() == DefaultFun.Bls12_381_G1_scalarMul).map(e -> e.argSummary()).toList();
        System.out.println("[PedersenG1Lib] scalarMul arguments for delta −250: " + scalarArgs);
        assertFalse(scalarArgs.isEmpty(), "the delta is applied with scalarMul");
        assertTrue(scalarArgs.stream().allMatch(a -> a.contains("250") && !a.contains("-250")), scalarArgs.toString());
        System.out.println("[PedersenG1Lib] public delta budget: " + measured.budgetConsumed());
        // Wrap-around below zero: C(10, r) − 11 opens to q − 1.
        BigInteger r = random();
        G1PedersenCommitment ten = PEDERSEN.commitScalar(BigInteger.TEN, r);
        assertSuccess(delta(ten.toPointBytes(), BigInteger.valueOf(-11), 8,
                PEDERSEN.commitScalar(Q.subtract(BigInteger.ONE), r).toPointBytes()));
        // 254 is refused too: at that width δ and δ − q could both pass the bound (spec §6.4).
        for (int k : new int[] {0, 254, 255, -1}) {
            assertRefusedBeforeScalarMul(delta(c.toPointBytes(), BigInteger.ONE, k, c.toPointBytes()), "deltaBits " + k);
        }
        assertFailure(delta(c.toPointBytes(), BigInteger.ONE, 8, c.toPointBytes()));
    }

    @Test
    @DisplayName("add, subtract and negate match the off-chain arithmetic")
    void sums() {
        G1PedersenCommitment a = PEDERSEN.commitScalar(random(), random());
        G1PedersenCommitment b = PEDERSEN.commitScalar(random(), random());
        assertSuccess(sum(a, b, 0, a.add(b)));
        assertSuccess(sum(a, b, 1, a.subtract(b)));
        assertSuccess(sum(a, b, 2, a.negate()));
        assertSuccess(sum(a, a, 1, G1PedersenCommitment.decode(HEX.parseHex(IDENTITY_HEX))));
        assertFailure(sum(a, b, 0, a.subtract(b)));
    }

    // ------------------------------------------------------------------ helpers

    private void assertOpening(String commitmentHex, BigInteger m, BigInteger r, boolean expected) {
        EvalResult result = opening(commitmentHex, m, r, BigInteger.ZERO);
        if (expected) {
            assertSuccess(result);
        } else {
            assertFailure(result);
        }
    }

    private EvalResult opening(String commitmentHex, BigInteger m, BigInteger r, BigInteger amountBits) {
        // amountBits 0 selects the unbounded check in these tests; the vector test probes width 0 itself.
        return run(PedersenG1OpeningProbe.class, PlutusData.bytes(HEX.parseHex(commitmentHex)),
                PlutusData.integer(m), PlutusData.integer(r), PlutusData.constr(amountBits.signum() == 0 ? 0 : 1),
                PlutusData.integer(amountBits));
    }

    private EvalResult bytesOpening(byte[] commitment, byte[] payload, BigInteger r) {
        return run(PedersenG1BytesProbe.class, PlutusData.bytes(commitment), PlutusData.bytes(payload), PlutusData.integer(r));
    }

    private EvalResult delta(byte[] commitment, BigInteger delta, int deltaBits, byte[] expected) {
        return run(PedersenG1DeltaProbe.class, PlutusData.bytes(commitment), PlutusData.integer(delta),
                PlutusData.integer(BigInteger.valueOf(deltaBits)), PlutusData.bytes(expected));
    }

    private EvalResult sum(G1PedersenCommitment a, G1PedersenCommitment b, int op, G1PedersenCommitment expected) {
        return run(PedersenG1SumProbe.class, PlutusData.bytes(a.toPointBytes()), PlutusData.bytes(b.toPointBytes()),
                PlutusData.integer(BigInteger.valueOf(op)), PlutusData.bytes(expected.toPointBytes()));
    }

    private EvalResult run(Class<?> probe, PlutusData... fields) {
        CompileResult result = compiled.computeIfAbsent(probe, p -> compileValidator(p, Path.of("src/test/java")));
        TxOutRef ref = TestDataBuilder.randomTxOutRef_typed();
        PlutusData ctx = spendingContext(ref, PlutusData.integer(0)).redeemer(PlutusData.constr(0, fields)).buildPlutusData();
        EvalResult evaluated = evaluate(result.program(), ctx);
        lastCounts = MarkedBuiltinCounts.count(result, ctx, evaluated.isSuccess());
        return evaluated;
    }

    private void assertRefusedBeforeScalarMul(EvalResult result, String label) {
        assertFalse(result.isSuccess(), label + ": must be refused");
        assertEquals(0, lastCounts.scalarMul(), label + ": scalarMul must not run");
        assertEquals(0, lastCounts.msm(), label + ": multiScalarMul must not run");
    }

    private static BigInteger random() {
        return G1Pedersen.randomBlinding(RANDOM);
    }

    private static byte[] pattern(int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (131 * i + 17);
        }
        return b;
    }
}
