package org.zeroj.blst;

import org.junit.jupiter.api.Test;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.bls12381.pedersen.G1Pedersen;
import org.zeroj.bls12381.pedersen.G1PedersenBytesCommitment;
import org.zeroj.bls12381.pedersen.G1PedersenCommitment;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ADR-0060 M2, invariant I7: the pure-Java and blst providers give byte-identical G1 Pedersen
 * commitments and identical verdicts and rejections ({@code pedersen-bls12-381-g1-v1} §8).
 *
 * <p>Expected values are copied from the spec (§10.2 scalars, §10.3 commitments); everything else is
 * a differential comparison between the two providers.
 */
class BlstG1PedersenParityTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final BlstBls12381Provider BLST_PROVIDER = BlstBls12381Provider.createDefault();
    private static final G1Pedersen PURE = G1Pedersen.pureJava();
    private static final G1Pedersen BLST = G1Pedersen.withProvider(BLST_PROVIDER);

    // Spec §1.
    private static final BigInteger Q =
            new BigInteger("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    // Spec §5.
    private static final long MAX_PAYLOAD_BYTES = 2305843009213693696L;

    // Spec §10.3: (m, r, C(m, r)).
    private static final Object[][] SPEC_COMMITMENTS = {
            {BigInteger.ZERO, BigInteger.ZERO,
                    "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
            {BigInteger.ONE, BigInteger.ZERO,
                    "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e"},
            {BigInteger.ZERO, BigInteger.ONE,
                    "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65"},
            {Q.subtract(BigInteger.ONE), Q.subtract(BigInteger.ONE),
                    "830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650"},
            {BigInteger.valueOf(12345), BigInteger.valueOf(67890),
                    "8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352cddecd632d2b758fc4"},
    };

    // Spec §10.2: pattern payload length → HashBytesToScalarG1 (decimal).
    private static final Map<Integer, String> SPEC_PATTERN_SCALARS = new LinkedHashMap<>();

    static {
        SPEC_PATTERN_SCALARS.put(0, "36315447437668222813564192209050807153821375512821708312164585800119004767398");
        SPEC_PATTERN_SCALARS.put(1, "17446826573447758279414620354847772216162392386874241427805739007456445167270");
        SPEC_PATTERN_SCALARS.put(55, "4769885727161205208895793752532058125538937305946508790125793345496789763442");
        SPEC_PATTERN_SCALARS.put(56, "44447803342360626358699221713325796379764762051949152351159963802212607565535");
        SPEC_PATTERN_SCALARS.put(64, "21158407019535989839516034496492483749423603674815396635618901986493989358291");
        SPEC_PATTERN_SCALARS.put(129, "10636700515201835153547363743684853122590858874478588016559740395075199699391");
        SPEC_PATTERN_SCALARS.put(1024, "51032631804351372587695208740820262018544153677477339797817422801122177762967");
    }

    private static final List<BigInteger> EDGE_SCALARS = List.of(
            BigInteger.ZERO, BigInteger.ONE, Q.subtract(BigInteger.ONE), BigInteger.ONE.shiftLeft(254));

    private static final int[] PAYLOAD_LENGTHS = {0, 1, 55, 56, 64, 129, 1024};

    @Test
    void blstSupportsGeneration() {
        assertTrue(BLST.supportsGeneration());
        assertSame(BLST_PROVIDER, BLST.provider());
        assertTrue(PURE.supportsGeneration());
    }

    @Test
    void commitScalar_specVectorsAreIdentical() {
        for (Object[] row : SPEC_COMMITMENTS) {
            BigInteger m = (BigInteger) row[0];
            BigInteger r = (BigInteger) row[1];
            String expected = (String) row[2];
            assertEquals(expected, HEX.formatHex(PURE.commitScalar(m, r).toPointBytes()), "pure " + m + ", " + r);
            assertEquals(expected, HEX.formatHex(BLST.commitScalar(m, r).toPointBytes()), "blst " + m + ", " + r);
        }
    }

    @Test
    void commitScalar_edgeAndRandomScalarsAreIdentical() {
        // 2^254 < q, so it is canonical (spec §1: ⌊log₂ q⌋ = 254).
        assertTrue(BigInteger.ONE.shiftLeft(254).compareTo(Q) < 0);
        for (BigInteger m : EDGE_SCALARS) {
            for (BigInteger r : EDGE_SCALARS) {
                assertScalarParity(m, r);
            }
        }
        Random random = new Random(0xADB_0060L);
        for (int i = 0; i < 40; i++) {
            BigInteger m = randomScalar(random);
            BigInteger r = randomScalar(random);
            assertScalarParity(m, r);
            assertScalarParity(m, BigInteger.ZERO);
            assertScalarParity(BigInteger.ZERO, r);
        }
    }

    @Test
    void commitBytes_specPatternPayloadsAreIdenticalAndMatchSpecScalars() throws Exception {
        Random random = new Random(0xB17E5L);
        for (Map.Entry<Integer, String> entry : SPEC_PATTERN_SCALARS.entrySet()) {
            byte[] payload = pattern(entry.getKey());
            BigInteger s = new BigInteger(entry.getValue());
            for (BigInteger r : List.of(BigInteger.ZERO, BigInteger.ONE, Q.subtract(BigInteger.ONE), randomScalar(random))) {
                byte[] expected = assertBytesParity(payload, r);
                // Spec §3: a bytes commitment to B is the scalar commitment to s = HashBytesToScalarG1(B).
                assertArrayEquals(PURE.commitScalar(s, r).toPointBytes(), expected, "pure, n = " + payload.length);
                assertArrayEquals(BLST.commitScalar(s, r).toPointBytes(), expected, "blst, n = " + payload.length);
            }
        }
    }

    @Test
    void commitBytes_randomPayloadsAreIdentical() throws Exception {
        Random random = new Random(0x0060_0002L);
        for (int length : PAYLOAD_LENGTHS) {
            for (int i = 0; i < 3; i++) {
                byte[] payload = new byte[length];
                random.nextBytes(payload);
                assertBytesParity(payload, randomScalar(random));
            }
        }
        for (int i = 0; i < 12; i++) {
            byte[] payload = new byte[random.nextInt(2048)];
            random.nextBytes(payload);
            assertBytesParity(payload, randomScalar(random));
        }
        for (BigInteger r : EDGE_SCALARS) {
            assertBytesParity(new byte[0], r);
        }
    }

    @Test
    void verification_verdictsAreIdentical() {
        Map<String, Op> cases = new LinkedHashMap<>();
        Random random = new Random(0x7E21_F1L);
        List<Object[]> openings = new ArrayList<>(Arrays.asList(SPEC_COMMITMENTS));
        for (int i = 0; i < 6; i++) {
            BigInteger m = randomScalar(random);
            BigInteger r = randomScalar(random);
            openings.add(new Object[]{m, r, HEX.formatHex(PURE.commitScalar(m, r).toPointBytes())});
        }
        for (Object[] row : openings) {
            BigInteger m = (BigInteger) row[0];
            BigInteger r = (BigInteger) row[1];
            G1PedersenCommitment c = G1PedersenCommitment.decode(HEX.parseHex((String) row[2]));
            G1PedersenCommitment tampered = c.withPublicDelta(BigInteger.ONE, 1);
            BigInteger mPlus = m.add(BigInteger.ONE).mod(Q);
            BigInteger rPlus = r.add(BigInteger.ONE).mod(Q);
            String id = m.toString(16) + "/" + r.toString(16);
            cases.put(id + " match", new Op("true", p -> p.verifyScalar(c, m, r)));
            cases.put(id + " match k=254", new Op(m.bitLength() <= 254 ? "true" : "reject:OUT_OF_RANGE",
                    p -> p.verifyScalar(c, m, r, 254)));
            cases.put(id + " wrong value", new Op("false", p -> p.verifyScalar(c, mPlus, r)));
            cases.put(id + " wrong blinding", new Op("false", p -> p.verifyScalar(c, m, rPlus)));
            cases.put(id + " tampered commitment", new Op("false", p -> p.verifyScalar(tampered, m, r)));
            cases.put(id + " tampered commitment, adjusted value", new Op("true", p -> p.verifyScalar(tampered, mPlus, r)));
        }

        BigInteger r = randomScalar(random);
        for (int length : PAYLOAD_LENGTHS) {
            byte[] payload = pattern(length);
            G1PedersenBytesCommitment b = PURE.commitBytes(payload, r);
            byte[] flipped = payload.clone();
            if (length > 0) {
                flipped[length - 1] ^= 0x01;
            }
            byte[] extended = Arrays.copyOf(payload, length + 1);
            String id = "bytes n=" + length;
            cases.put(id + " match", new Op("true", p -> p.verifyBytes(b, payload, r)));
            cases.put(id + " stream match", new Op("true",
                    p -> p.verifyBytes(b, new ByteArrayInputStream(payload), length, r)));
            cases.put(id + " toEnd match", new Op("true",
                    p -> p.verifyBytesToEnd(b, new ByteArrayInputStream(payload), length + 7, r)));
            if (length > 0) {
                cases.put(id + " flipped bit", new Op("false", p -> p.verifyBytes(b, flipped, r)));
                cases.put(id + " truncated", new Op("false", p -> p.verifyBytes(b, Arrays.copyOf(payload, length - 1), r)));
                cases.put(id + " stream early end", new Op("error:IOException",
                        p -> p.verifyBytes(b, new ByteArrayInputStream(payload, 0, length - 1), length, r)));
            }
            cases.put(id + " extended", new Op("false", p -> p.verifyBytes(b, extended, r)));
            cases.put(id + " stream excess", new Op("error:IOException",
                    p -> p.verifyBytes(b, new ByteArrayInputStream(extended), length, r)));
            cases.put(id + " toEnd over max", new Op("error:IOException",
                    p -> p.verifyBytesToEnd(b, new ByteArrayInputStream(extended), length, r)));
            cases.put(id + " wrong blinding", new Op("false", p -> p.verifyBytes(b, payload, r.add(BigInteger.ONE).mod(Q))));
        }

        for (Map.Entry<String, Op> entry : cases.entrySet()) {
            String pure = outcome(PURE, entry.getValue());
            String blst = outcome(BLST, entry.getValue());
            assertEquals(entry.getValue().expected(), pure, "pure: " + entry.getKey());
            assertEquals(pure, blst, "blst: " + entry.getKey());
        }
    }

    @Test
    void rejections_areIdentical() {
        G1PedersenCommitment c = PURE.commitScalar(BigInteger.valueOf(12345), BigInteger.valueOf(67890));
        G1PedersenBytesCommitment b = PURE.commitBytes(new byte[]{1, 2, 3}, BigInteger.TWO);
        BigInteger minusOne = BigInteger.ONE.negate();
        BigInteger qPlusOne = Q.add(BigInteger.ONE);
        Map<String, Op> cases = new LinkedHashMap<>();
        String ncs = "reject:NON_CANONICAL_SCALAR";
        String cfg = "reject:INVALID_CONFIGURATION";
        String oor = "reject:OUT_OF_RANGE";
        String len = "reject:LENGTH_OUT_OF_RANGE";
        for (BigInteger bad : List.of(Q, qPlusOne, minusOne)) {
            String id = "scalar " + bad;
            cases.put("commitScalar value " + id, new Op(ncs, p -> p.commitScalar(bad, BigInteger.ONE) != null));
            cases.put("commitScalar blinding " + id, new Op(ncs, p -> p.commitScalar(BigInteger.ONE, bad) != null));
            cases.put("verifyScalar value " + id, new Op(ncs, p -> p.verifyScalar(c, bad, BigInteger.ONE)));
            cases.put("verifyScalar blinding " + id, new Op(ncs, p -> p.verifyScalar(c, BigInteger.ONE, bad)));
            cases.put("verifyScalar4 value " + id, new Op(ncs, p -> p.verifyScalar(c, bad, BigInteger.ONE, 254)));
            cases.put("commitBytes blinding " + id, new Op(ncs, p -> p.commitBytes(new byte[3], bad) != null));
            cases.put("commitBytes stream blinding " + id,
                    new Op(ncs, p -> p.commitBytes(new ByteArrayInputStream(new byte[3]), 3, bad) != null));
            cases.put("commitBytesToEnd blinding " + id,
                    new Op(ncs, p -> p.commitBytesToEnd(new ByteArrayInputStream(new byte[3]), 3, bad) != null));
            cases.put("verifyBytes blinding " + id, new Op(ncs, p -> p.verifyBytes(b, new byte[3], bad)));
        }
        for (int bits : new int[]{0, -1, 255, Integer.MAX_VALUE, Integer.MIN_VALUE}) {
            cases.put("amountBits " + bits, new Op(cfg, p -> p.verifyScalar(c, BigInteger.ONE, BigInteger.ONE, bits)));
        }
        // Check 2 at 2^k − 1 (accepted, then the equation) and 2^k (rejected).
        cases.put("check 2 at 2^14 - 1", new Op("false", p -> p.verifyScalar(c, BigInteger.valueOf(16383), BigInteger.ONE, 14)));
        cases.put("check 2 at 2^14", new Op(oor, p -> p.verifyScalar(c, BigInteger.valueOf(16384), BigInteger.ONE, 14)));
        cases.put("check 2 at 2^13 for 12345", new Op(oor,
                p -> p.verifyScalar(c, BigInteger.valueOf(12345), BigInteger.valueOf(67890), 13)));
        for (long bound : new long[]{-1, MAX_PAYLOAD_BYTES + 1, Long.MIN_VALUE, Long.MAX_VALUE}) {
            cases.put("commitBytes length " + bound, new Op(len,
                    p -> p.commitBytes(new ByteArrayInputStream(new byte[0]), bound, BigInteger.ONE) != null));
            cases.put("commitBytesToEnd maxBytes " + bound, new Op(len,
                    p -> p.commitBytesToEnd(new ByteArrayInputStream(new byte[0]), bound, BigInteger.ONE) != null));
            cases.put("verifyBytes length " + bound, new Op(len,
                    p -> p.verifyBytes(b, new ByteArrayInputStream(new byte[0]), bound, BigInteger.ONE)));
            cases.put("verifyBytesToEnd maxBytes " + bound, new Op(len,
                    p -> p.verifyBytesToEnd(b, new ByteArrayInputStream(new byte[0]), bound, BigInteger.ONE)));
        }
        // Check order: a non-canonical blinding is reported before a bad length.
        cases.put("blinding before length", new Op(ncs,
                p -> p.commitBytes(new ByteArrayInputStream(new byte[0]), -1, Q) != null));
        cases.put("nulls first", new Op("error:NullPointerException", p -> p.commitScalar(null, Q) != null));

        for (Map.Entry<String, Op> entry : cases.entrySet()) {
            String pure = outcome(PURE, entry.getValue());
            String blst = outcome(BLST, entry.getValue());
            assertEquals(entry.getValue().expected(), pure, "pure: " + entry.getKey());
            assertEquals(pure, blst, "blst: " + entry.getKey());
        }
    }

    @Test
    void crossProviderOpenings_verify() {
        Random random = new Random(0xC205_5L);
        for (int i = 0; i < 8; i++) {
            BigInteger m = randomScalar(random);
            BigInteger r = randomScalar(random);
            assertTrue(BLST.verifyScalar(PURE.commitScalar(m, r), m, r));
            assertTrue(PURE.verifyScalar(BLST.commitScalar(m, r), m, r));
            byte[] payload = new byte[random.nextInt(300)];
            random.nextBytes(payload);
            assertTrue(BLST.verifyBytes(PURE.commitBytes(payload, r), payload, r));
            assertTrue(PURE.verifyBytes(BLST.commitBytes(payload, r), payload, r));
        }
    }

    // ---- helpers ----

    private static void assertScalarParity(BigInteger m, BigInteger r) {
        byte[] pure = PURE.commitScalar(m, r).toPointBytes();
        byte[] blst = BLST.commitScalar(m, r).toPointBytes();
        assertArrayEquals(pure, blst, () -> "m = " + m.toString(16) + ", r = " + r.toString(16));
        assertTrue(PURE.verifyScalar(G1PedersenCommitment.decode(blst), m, r));
        assertTrue(BLST.verifyScalar(G1PedersenCommitment.decode(pure), m, r));
    }

    /** All three payload sources on both providers give one encoding; returns it. */
    private static byte[] assertBytesParity(byte[] payload, BigInteger r) throws Exception {
        byte[] expected = PURE.commitBytes(payload, r).toPointBytes();
        String id = "n = " + payload.length;
        for (G1Pedersen p : List.of(PURE, BLST)) {
            String who = (p == PURE ? "pure " : "blst ") + id;
            assertArrayEquals(expected, p.commitBytes(payload, r).toPointBytes(), who + " array");
            assertArrayEquals(expected,
                    p.commitBytes(new ByteArrayInputStream(payload), payload.length, r).toPointBytes(), who + " stream");
            assertArrayEquals(expected,
                    p.commitBytesToEnd(new ByteArrayInputStream(payload), payload.length, r).toPointBytes(), who + " toEnd");
            assertTrue(p.verifyBytes(G1PedersenBytesCommitment.decode(expected), payload, r), who + " verify");
        }
        return expected;
    }

    /** Spec §10.2 pattern payload: octet i is (131·i + 17) mod 256. */
    private static byte[] pattern(int length) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) ((131 * i + 17) % 256);
        }
        return out;
    }

    private static BigInteger randomScalar(Random random) {
        BigInteger x;
        do {
            x = new BigInteger(255, random);
        } while (x.compareTo(Q) >= 0);
        return x;
    }

    private static String outcome(G1Pedersen pedersen, Op op) {
        try {
            return Boolean.toString(op.call().run(pedersen));
        } catch (CommitmentFormatException e) {
            return "reject:" + e.reason();
        } catch (Exception e) {
            return "error:" + e.getClass().getSimpleName();
        }
    }

    @FunctionalInterface
    private interface Call {
        boolean run(G1Pedersen pedersen) throws Exception;
    }

    private record Op(String expected, Call call) {
    }
}
