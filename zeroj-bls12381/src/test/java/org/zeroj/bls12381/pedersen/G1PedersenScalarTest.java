package org.zeroj.bls12381.pedersen;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.zeroj.api.commitment.CommitmentEnvelope;
import org.zeroj.api.commitment.CommitmentError;
import org.zeroj.api.commitment.CommitmentFormatException;
import org.zeroj.api.commitment.CommitmentGroup;
import org.zeroj.api.commitment.CommitmentKey;
import org.zeroj.api.commitment.CommitmentKind;
import org.zeroj.api.commitment.CommitmentProfiles;
import org.zeroj.bls12381.pedersen.G1PedersenDecoderTest.Ref;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code pedersen-bls12-381-g1-v1}: the §10.3 commitments, checks 1 and 2 (§6.3), the public delta and
 * sums (§6.4), the opening and blinding encodings (§6.1, §6.2), the scalar snapshot (§7), the §8
 * check order, and the envelope and expected-profile rules of {@code commitment-profiles-v1} §9 and
 * §12. Expected points come from the spec tables or from the independent {@link Ref} arithmetic.
 */
class G1PedersenScalarTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final G1Pedersen PEDERSEN = G1Pedersen.pureJava();

    private static final BigInteger Q = Ref.Q;
    private static final BigInteger Q_MINUS_1 = Q.subtract(BigInteger.ONE);
    private static final BigInteger TWO_256_MINUS_1 = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
    private static final List<BigInteger> NON_CANONICAL =
            List.of(Q, Q.add(BigInteger.ONE), BigInteger.ONE.negate(), TWO_256_MINUS_1, Q.negate());
    private static final int[] INVALID_BITS = {0, 255, -1, Integer.MIN_VALUE, Integer.MAX_VALUE};

    // spec §10.3
    private static final String C_0_0 = "c0" + "00".repeat(47);
    private static final String C_1_0 = "80453f5474382da080469962f6e656ba694287604b6fc18c26bfd2197b2c16644e56e5c43c76ba9869e960e3fd5c2f3e";
    private static final String C_0_1 = "92e04e91b89753df710400b28abb7d8aa6a0958a6d90e418a405af12559419d772eb1111aafc6b64875b9a2256b6ab65";
    private static final String C_QM1_QM1 = "830c22c1792dae9774b23f9c31801a964094bef7734745f4012b4e5c133a5d608636f1e020d68cb2688ad276369b8650";
    private static final String C_12345_67890 = "8c5b1e42a3912ecf2a2fc27a26ef67afd30799614ebfbd5dc7a2cb00e43b063a60a4d516007352cddecd632d2b758fc4";

    // ---- §10.3 ----

    @Test
    @DisplayName("§10.3: the five pinned commitments, each verified, and reproduced by the independent reference")
    void specCommitments() {
        Object[][] rows = {
                {BigInteger.ZERO, BigInteger.ZERO, C_0_0},
                {BigInteger.ONE, BigInteger.ZERO, C_1_0},
                {BigInteger.ZERO, BigInteger.ONE, C_0_1},
                {Q_MINUS_1, Q_MINUS_1, C_QM1_QM1},
                {BigInteger.valueOf(12345), BigInteger.valueOf(67890), C_12345_67890}};
        for (Object[] row : rows) {
            BigInteger m = (BigInteger) row[0], r = (BigInteger) row[1];
            G1PedersenCommitment c = PEDERSEN.commitScalar(m, r);
            assertEquals(row[2], HEX.formatHex(c.toPointBytes()), "C(" + m + ", " + r + ")");
            assertEquals(c, G1PedersenCommitment.decode(HEX.parseHex((String) row[2])));
            assertTrue(PEDERSEN.verifyScalar(c, m, r));
            assertEquals(row[2], HEX.formatHex(Ref.compress(Ref.add(Ref.mul(Ref.G, m), Ref.mul(Ref.H, r)))));
        }
        // C(0, 0) = O, C(1, 0) = G, C(0, 1) = H and C(q − 1, q − 1) = −(G + H).
        assertArrayEquals(G1PedersenDecoderTest.identityBytes(), HEX.parseHex(C_0_0));
        assertEquals(G1PedersenBases.G_HEX, C_1_0);
        assertEquals(G1PedersenBases.H_HEX, C_0_1);
        assertEquals(C_QM1_QM1, HEX.formatHex(Ref.compress(Ref.neg(Ref.add(Ref.G, Ref.H)))));
        G1PedersenCommitment g = G1PedersenCommitment.decode(HEX.parseHex(C_1_0));
        G1PedersenCommitment h = G1PedersenCommitment.decode(HEX.parseHex(C_0_1));
        assertEquals(g.add(h).negate(), PEDERSEN.commitScalar(Q_MINUS_1, Q_MINUS_1));
        assertFalse(PEDERSEN.verifyScalar(g, BigInteger.ZERO, BigInteger.ONE), "G and H are not swapped");
        assertFalse(PEDERSEN.verifyScalar(h, BigInteger.ONE, BigInteger.ZERO), "G and H are not swapped");
    }

    // ---- check 1 ----

    @Test
    @DisplayName("Check 1: q − 1 is accepted for value and blinding on every strict path")
    void checkOneAcceptsQMinus1() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(Q_MINUS_1, Q_MINUS_1);
        assertTrue(PEDERSEN.verifyScalar(c, Q_MINUS_1, Q_MINUS_1));
        G1PedersenCommitment small = PEDERSEN.commitScalar(BigInteger.ONE, Q_MINUS_1);
        assertTrue(PEDERSEN.verifyScalar(small, BigInteger.ONE, Q_MINUS_1, 1));
        G1PedersenOpening opening = G1PedersenOpening.of(Q_MINUS_1, Q_MINUS_1);
        assertEquals(Q_MINUS_1, opening.value());
        assertEquals(Q_MINUS_1, opening.blinding());
        assertEquals(HEX.formatHex(i2osp32(Q_MINUS_1)), HEX.formatHex(G1PedersenBlinding.encode(Q_MINUS_1)));
    }

    @Test
    @DisplayName("Check 1: q, q + 1, −1, 2^256 − 1 and −q are NON_CANONICAL_SCALAR, never reduced, on every strict path")
    void checkOneRejects() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ZERO, r);
        for (BigInteger bad : NON_CANONICAL) {
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.commitScalar(bad, r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.commitScalar(BigInteger.ONE, bad));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, bad, r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, BigInteger.ZERO, bad));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, bad, r, 254));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, BigInteger.ZERO, bad, 254));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.of(bad, r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.of(BigInteger.ONE, bad));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenBlinding.encode(bad));
        }
        // q ≡ 0 would open C(0, r) if it were reduced; it must not.
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, Q, r));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, BigInteger.ZERO, r.add(Q)));
    }

    @Test
    @DisplayName("Rejection messages never contain the scalar")
    void noSecretInMessages() {
        BigInteger secret = Q.add(BigInteger.valueOf(987654321));
        List<Executable> calls = List.of(
                () -> PEDERSEN.commitScalar(secret, BigInteger.ONE),
                () -> PEDERSEN.commitScalar(BigInteger.ONE, secret),
                () -> G1PedersenOpening.of(secret, BigInteger.ONE),
                () -> G1PedersenBlinding.encode(secret),
                () -> G1PedersenOpening.decode(concat(i2osp32(secret), new byte[32])),
                () -> G1PedersenBlinding.decode(i2osp32(secret)));
        for (Executable call : calls) {
            String message = assertThrows(CommitmentFormatException.class, call).getMessage();
            assertFalse(message.contains(secret.toString()) || message.contains(secret.toString(16)), message);
        }
    }

    // ---- check 2 ----

    @Test
    @DisplayName("Check 2: 2^k − 1 verifies and 2^k (a valid residue) is OUT_OF_RANGE, for k in {1, 64, 252, 253, 254}")
    void checkTwo() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        for (int k : new int[]{1, 64, 252, 253, 254}) {
            BigInteger max = BigInteger.ONE.shiftLeft(k).subtract(BigInteger.ONE);
            assertTrue(PEDERSEN.verifyScalar(PEDERSEN.commitScalar(max, r), max, r, k), "k = " + k);
            BigInteger over = BigInteger.ONE.shiftLeft(k);
            G1PedersenCommitment c = PEDERSEN.commitScalar(over, r);
            assertTrue(PEDERSEN.verifyScalar(c, over, r), "2^" + k + " is a canonical residue");
            assertError(CommitmentError.OUT_OF_RANGE, () -> PEDERSEN.verifyScalar(c, over, r, k));
            assertFalse(PEDERSEN.verifyScalar(c, max, r, k), "in range, wrong value");
        }
        // q − 1 ≥ 2^254: a canonical residue that the widest bound still rejects.
        G1PedersenCommitment top = PEDERSEN.commitScalar(Q_MINUS_1, r);
        assertError(CommitmentError.OUT_OF_RANGE, () -> PEDERSEN.verifyScalar(top, Q_MINUS_1, r, 254));
        // Check 2 never applies to the blinding.
        G1PedersenCommitment bigBlinding = PEDERSEN.commitScalar(BigInteger.ONE, Q_MINUS_1);
        assertTrue(PEDERSEN.verifyScalar(bigBlinding, BigInteger.ONE, Q_MINUS_1, 1));
    }

    @Test
    @DisplayName("Check 2: amountBits 0, 255, −1, Integer.MIN_VALUE and Integer.MAX_VALUE are INVALID_CONFIGURATION")
    void invalidAmountBits() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE);
        for (int k : INVALID_BITS) {
            assertError(CommitmentError.INVALID_CONFIGURATION, () -> PEDERSEN.verifyScalar(c, BigInteger.ONE, BigInteger.ONE, k));
        }
    }

    @Test
    @DisplayName("§8 order: nulls, then amountBits, then value check 1, then blinding check 1, then check 2")
    void checkOrder() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE);
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyScalar(c, null, Q, 0));
        assertThrows(NullPointerException.class, () -> PEDERSEN.verifyScalar(null, Q, Q, 0));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PEDERSEN.verifyScalar(c, Q, Q, 0));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> PEDERSEN.verifyScalar(c, BigInteger.ONE.shiftLeft(300), Q, 255));
        for (Executable bothBad : List.<Executable>of(
                () -> PEDERSEN.commitScalar(Q, Q),
                () -> PEDERSEN.verifyScalar(c, Q, Q),
                () -> PEDERSEN.verifyScalar(c, Q, Q, 8),
                () -> G1PedersenOpening.of(Q, Q))) {
            String message = assertError(CommitmentError.NON_CANONICAL_SCALAR, bothBad).getMessage();
            assertTrue(message.contains("value") && !message.contains("blinding"), "value is checked first: " + message);
        }
        String blindingMessage = assertError(CommitmentError.NON_CANONICAL_SCALAR,
                () -> PEDERSEN.verifyScalar(c, BigInteger.ONE, Q, 8)).getMessage();
        assertTrue(blindingMessage.contains("blinding"), blindingMessage);
        // An over-bound value with a bad blinding fails check 1 first; with a good blinding, check 2.
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, BigInteger.valueOf(256), Q, 8));
        assertError(CommitmentError.OUT_OF_RANGE, () -> PEDERSEN.verifyScalar(c, BigInteger.valueOf(256), BigInteger.ONE, 8));
    }

    @Test
    @DisplayName("Every strict entry point rejects null arguments with NullPointerException")
    void nulls() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE);
        BigInteger one = BigInteger.ONE;
        List<Executable> calls = List.of(
                () -> PEDERSEN.commitScalar(null, one),
                () -> PEDERSEN.commitScalar(one, null),
                () -> PEDERSEN.verifyScalar(null, one, one),
                () -> PEDERSEN.verifyScalar(c, null, one),
                () -> PEDERSEN.verifyScalar(c, one, null),
                () -> PEDERSEN.verifyScalar(null, one, one, 8),
                () -> PEDERSEN.verifyScalar(c, one, null, 8),
                () -> G1PedersenOpening.of(null, one),
                () -> G1PedersenOpening.of(one, null),
                () -> G1PedersenOpening.decode(null),
                () -> G1PedersenBlinding.encode(null),
                () -> G1PedersenBlinding.decode(null),
                () -> c.withPublicDelta(null, 8),
                () -> c.withPublicDelta(null, 0),
                () -> c.add(null),
                () -> c.subtract(null),
                () -> G1Pedersen.randomBlinding(null),
                () -> G1Pedersen.withProvider(null));
        for (Executable call : calls) {
            assertThrows(NullPointerException.class, call);
        }
    }

    // ---- public delta (§6.4) ----

    @Test
    @DisplayName("withPublicDelta: ±(2^k − 1) is accepted and ±2^k is OUT_OF_RANGE, for k in {1, 64, 253}")
    void deltaBounds() {
        BigInteger m = BigInteger.valueOf(1000);
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment c = PEDERSEN.commitScalar(m, r);
        for (int k : new int[]{1, 64, 253}) {
            BigInteger max = BigInteger.ONE.shiftLeft(k).subtract(BigInteger.ONE);
            for (BigInteger delta : List.of(max, max.negate())) {
                G1PedersenCommitment moved = c.withPublicDelta(delta, k);
                assertEquals(PEDERSEN.commitScalar(m.add(delta).mod(Q), r), moved, "δ = " + delta);
            }
            BigInteger over = BigInteger.ONE.shiftLeft(k);
            assertError(CommitmentError.OUT_OF_RANGE, () -> c.withPublicDelta(over, k));
            assertError(CommitmentError.OUT_OF_RANGE, () -> c.withPublicDelta(over.negate(), k));
        }
        for (BigInteger huge : List.of(Q, Q.negate(), Q_MINUS_1, TWO_256_MINUS_1, TWO_256_MINUS_1.negate())) {
            assertError(CommitmentError.OUT_OF_RANGE, () -> c.withPublicDelta(huge, 253));
        }
    }

    @Test
    @DisplayName("withPublicDelta: deltaBits 254 is INVALID_CONFIGURATION, so no δ − q alias can pass the bound")
    void deltaAliasExcluded() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE);
        // At width 254, δ = 2^254 − 1 and δ − q both satisfy |δ| < 2^254 and give the same point.
        BigInteger delta = BigInteger.ONE.shiftLeft(254).subtract(BigInteger.ONE);
        BigInteger alias = delta.subtract(Q);
        assertTrue(alias.abs().compareTo(BigInteger.ONE.shiftLeft(254)) < 0, "the alias exists at 254");
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> c.withPublicDelta(delta, 254));
        assertError(CommitmentError.INVALID_CONFIGURATION, () -> c.withPublicDelta(alias, 254));
        // At 253 the signed range (−2^253, 2^253) holds fewer than q integers: no two are congruent.
        assertTrue(BigInteger.ONE.shiftLeft(254).subtract(BigInteger.ONE).compareTo(Q) <= 0);
        BigInteger top = BigInteger.ONE.shiftLeft(253).subtract(BigInteger.ONE);
        assertError(CommitmentError.OUT_OF_RANGE, () -> c.withPublicDelta(top.subtract(Q), 253));
        // Check 2 keeps width 254: m is non-negative and 2^254 < q.
        assertTrue(PEDERSEN.verifyScalar(PEDERSEN.commitScalar(top, BigInteger.ONE), top, BigInteger.ONE, 254));
    }

    @Test
    @DisplayName("withPublicDelta: deltaBits 0, 255, −1, MIN and MAX are INVALID_CONFIGURATION, checked before the bound")
    void deltaInvalidBits() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.ONE);
        for (int k : INVALID_BITS) {
            assertError(CommitmentError.INVALID_CONFIGURATION, () -> c.withPublicDelta(BigInteger.ONE, k));
            assertError(CommitmentError.INVALID_CONFIGURATION, () -> c.withPublicDelta(BigInteger.ONE.shiftLeft(400), k));
        }
    }

    @Test
    @DisplayName("withPublicDelta: C(m, r) + [δ]G = C((m + δ) mod q, r), with wrap-around below 0 and above q − 1, and δ = 0")
    void deltaCorrectness() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        Object[][] cases = {
                {BigInteger.valueOf(5), BigInteger.valueOf(-7), 8},
                {Q.subtract(BigInteger.valueOf(3)), BigInteger.TEN, 8},
                {BigInteger.valueOf(100), BigInteger.ONE.shiftLeft(253).subtract(BigInteger.ONE).negate(), 253},
                {Q_MINUS_1, BigInteger.ONE.shiftLeft(253).subtract(BigInteger.ONE), 253},
                {BigInteger.ZERO, BigInteger.valueOf(-1), 1},
                {BigInteger.valueOf(42), BigInteger.valueOf(58), 7}};
        for (Object[] row : cases) {
            BigInteger m = (BigInteger) row[0], delta = (BigInteger) row[1];
            G1PedersenCommitment moved = PEDERSEN.commitScalar(m, r).withPublicDelta(delta, (Integer) row[2]);
            BigInteger expected = m.add(delta).mod(Q);
            assertEquals(PEDERSEN.commitScalar(expected, r), moved, "m = " + m + ", δ = " + delta);
            assertTrue(PEDERSEN.verifyScalar(moved, expected, r));
        }
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.TEN, r);
        assertEquals(c, c.withPublicDelta(BigInteger.ZERO, 1));
        // Independent anchor: G + [−2]G = −G, from the reference arithmetic.
        G1PedersenCommitment g = G1PedersenCommitment.decode(HEX.parseHex(C_1_0));
        assertEquals(HEX.formatHex(Ref.compress(Ref.neg(Ref.G))),
                HEX.formatHex(g.withPublicDelta(BigInteger.valueOf(-2), 2).toPointBytes()));
        assertEquals(C_0_0, HEX.formatHex(g.withPublicDelta(BigInteger.valueOf(-1), 1).toPointBytes()));
    }

    // ---- sums (§6.4) ----

    @Test
    @DisplayName("add, subtract and negate open to residues mod q of both value and blinding")
    void homomorphism() {
        BigInteger a = Q.subtract(BigInteger.valueOf(5)), b = BigInteger.valueOf(7);
        BigInteger r1 = G1Pedersen.randomBlinding(RANDOM), r2 = G1Pedersen.randomBlinding(RANDOM);
        G1PedersenCommitment ca = PEDERSEN.commitScalar(a, r1);
        G1PedersenCommitment cb = PEDERSEN.commitScalar(b, r2);
        G1PedersenCommitment sum = ca.add(cb);
        assertEquals(BigInteger.TWO, a.add(b).mod(Q));
        assertTrue(PEDERSEN.verifyScalar(sum, BigInteger.TWO, r1.add(r2).mod(Q)));
        assertEquals(PEDERSEN.commitScalar(BigInteger.TWO, r1.add(r2).mod(Q)), sum);
        G1PedersenCommitment diff = cb.subtract(ca);
        assertTrue(PEDERSEN.verifyScalar(diff, b.subtract(a).mod(Q), r2.subtract(r1).mod(Q)));
        assertEquals(BigInteger.valueOf(12), b.subtract(a).mod(Q));
        assertTrue(PEDERSEN.verifyScalar(ca.negate(), a.negate().mod(Q), r1.negate().mod(Q)));
        assertEquals(ca.subtract(cb), ca.add(cb.negate()));
        G1PedersenCommitment identity = G1PedersenCommitment.decode(HEX.parseHex(C_0_0));
        assertEquals(identity, ca.add(ca.negate()));
        assertEquals(identity, ca.subtract(ca));
        assertEquals(identity, identity.negate());
        assertEquals(ca, ca.add(identity));
        assertSame(G1PedersenCommitment.PROFILE, sum.profile());
    }

    // ---- opening and blinding encodings (§6.1, §6.2) ----

    @Test
    @DisplayName("Opening: I2OSP(m, 32) ‖ I2OSP(r, 32), round trip, lengths 63/65 MALFORMED, m ≥ q then r ≥ q NON_CANONICAL")
    void openingEncoding() {
        BigInteger m = new BigInteger("0102030405060708090a0b0c0d0e0f", 16);
        BigInteger r = Q_MINUS_1;
        byte[] expected = HEX.parseHex(String.format("%064x%064x", m, r));
        G1PedersenOpening opening = G1PedersenOpening.of(m, r);
        assertArrayEquals(expected, opening.encode());
        G1PedersenOpening decoded = G1PedersenOpening.decode(expected);
        assertEquals(m, decoded.value());
        assertEquals(r, decoded.blinding());
        assertArrayEquals(new byte[64], G1PedersenOpening.of(BigInteger.ZERO, BigInteger.ZERO).encode());
        assertEquals(BigInteger.ZERO, G1PedersenOpening.decode(new byte[64]).value());
        byte[] fresh = opening.encode();
        fresh[0] = 9;
        assertArrayEquals(expected, opening.encode(), "encode returns a fresh array");

        for (int length : new int[]{0, 32, 63, 65, 96, 128}) {
            assertError(CommitmentError.MALFORMED_ENCODING, () -> G1PedersenOpening.decode(new byte[length]));
        }
        // A wrong length wins over non-canonical scalars.
        assertError(CommitmentError.MALFORMED_ENCODING, () -> G1PedersenOpening.decode(Arrays.copyOf(concat(i2osp32(Q), i2osp32(Q)), 65)));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.decode(concat(i2osp32(Q), new byte[32])));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.decode(concat(new byte[32], i2osp32(Q))));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.decode(concat(i2osp32(TWO_256_MINUS_1), new byte[32])));
        String message = assertError(CommitmentError.NON_CANONICAL_SCALAR,
                () -> G1PedersenOpening.decode(concat(i2osp32(Q), i2osp32(Q)))).getMessage();
        assertTrue(message.contains("value") && !message.contains("blinding"), "m is checked before r: " + message);
        assertTrue(assertError(CommitmentError.NON_CANONICAL_SCALAR,
                () -> G1PedersenOpening.decode(concat(new byte[32], i2osp32(Q)))).getMessage().contains("blinding"));
        // Decoding applies no amount bound.
        assertEquals(Q_MINUS_1, G1PedersenOpening.decode(concat(i2osp32(Q_MINUS_1), i2osp32(Q_MINUS_1))).value());
    }

    @Test
    @DisplayName("Blinding: I2OSP(r, 32), round trip, lengths 31/33 MALFORMED, r ≥ q NON_CANONICAL")
    void blindingEncoding() {
        for (BigInteger r : List.of(BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(0x1234), Q_MINUS_1)) {
            byte[] expected = HEX.parseHex(String.format("%064x", r));
            assertArrayEquals(expected, G1PedersenBlinding.encode(r));
            assertEquals(r, G1PedersenBlinding.decode(expected));
        }
        for (int length : new int[]{0, 31, 33, 48, 64}) {
            assertError(CommitmentError.MALFORMED_ENCODING, () -> G1PedersenBlinding.decode(new byte[length]));
        }
        assertError(CommitmentError.MALFORMED_ENCODING, () -> G1PedersenBlinding.decode(Arrays.copyOf(i2osp32(Q), 33)));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenBlinding.decode(i2osp32(Q)));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenBlinding.decode(i2osp32(TWO_256_MINUS_1)));
    }

    @Test
    @DisplayName("Opening holder: redacted toString, identity equality only")
    void openingIsRedacted() {
        BigInteger m = new BigInteger("1234567890abcdef1234567890", 16);
        BigInteger r = new BigInteger("fedcba0987654321fedcba", 16);
        G1PedersenOpening opening = G1PedersenOpening.of(m, r);
        String text = opening.toString();
        for (BigInteger secret : List.of(m, r)) {
            assertFalse(text.contains(secret.toString()) || text.contains(secret.toString(16)), text);
        }
        assertThrows(NoSuchMethodException.class, () -> G1PedersenOpening.class.getDeclaredMethod("equals", Object.class));
        assertThrows(NoSuchMethodException.class, () -> G1PedersenOpening.class.getDeclaredMethod("hashCode"));
        assertNotEquals(opening, G1PedersenOpening.of(m, r));
    }

    // ---- scalar snapshot (§7) ----

    @Test
    @DisplayName("§7: a BigInteger subclass that lies about its range through every observer still fails check 1")
    void hostileRangeLiar() {
        BigInteger probe = liar(Q);
        assertTrue(probe.signum() > 0 && probe.compareTo(Q) < 0 && probe.bitLength() == 1 && probe.abs().equals(BigInteger.ONE),
                "the fixture fools a check that consults the argument's own methods");
        BigInteger r = BigInteger.ONE;
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ZERO, r);
        for (BigInteger bad : NON_CANONICAL) {
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.commitScalar(liar(bad), r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.commitScalar(BigInteger.ONE, liar(bad)));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, liar(bad), r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, BigInteger.ZERO, liar(bad)));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(c, liar(bad), r, 8));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.of(liar(bad), r));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.of(BigInteger.ONE, liar(bad)));
            assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenBlinding.encode(liar(bad)));
        }
        // Lies about bitLength, abs and signum do not pass check 2 or the delta bound.
        BigInteger big = BigInteger.ONE.shiftLeft(64);
        G1PedersenCommitment cBig = PEDERSEN.commitScalar(big, r);
        assertError(CommitmentError.OUT_OF_RANGE, () -> PEDERSEN.verifyScalar(cBig, liar(big), r, 8));
        assertError(CommitmentError.OUT_OF_RANGE, () -> c.withPublicDelta(liar(big), 8));
        assertError(CommitmentError.OUT_OF_RANGE, () -> c.withPublicDelta(liar(big.negate()), 8));
    }

    @Test
    @DisplayName("§7: a subclass whose value changes after the first read is checked, used and retained as that first value")
    void hostileShapeshifter() {
        BigInteger r = G1Pedersen.randomBlinding(RANDOM);
        BigInteger ten = BigInteger.TEN;
        BigInteger later = Q.add(BigInteger.valueOf(5));

        HostileBigInteger value = new HostileBigInteger(later, ten, later);
        G1PedersenOpening opening = G1PedersenOpening.of(value, BigInteger.ONE);
        assertSame(BigInteger.class, opening.value().getClass());
        assertEquals(ten, opening.value());
        assertEquals(1, value.reads, "the argument is read exactly once");
        assertTrue(value.handedOutWiped(), "the copy's temporary octets are wiped");

        HostileBigInteger blinding = new HostileBigInteger(later, r, later);
        G1PedersenOpening o2 = G1PedersenOpening.of(BigInteger.ONE, blinding);
        assertSame(BigInteger.class, o2.blinding().getClass());
        assertEquals(r, o2.blinding());

        G1PedersenCommitment expected = PEDERSEN.commitScalar(ten, r);
        assertEquals(expected, PEDERSEN.commitScalar(new HostileBigInteger(later, ten, later), new HostileBigInteger(later, r, later)));
        assertTrue(PEDERSEN.verifyScalar(expected, new HostileBigInteger(later, ten, later), new HostileBigInteger(later, r, later)));
        assertTrue(PEDERSEN.verifyScalar(expected, new HostileBigInteger(later, ten, later), r, 4));
        assertArrayEquals(i2osp32(r), G1PedersenBlinding.encode(new HostileBigInteger(later, r, later)));

        // The reverse: non-canonical on the first read, canonical afterwards, is rejected.
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenOpening.of(new HostileBigInteger(ten, Q, ten), BigInteger.ONE));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.commitScalar(new HostileBigInteger(ten, Q, ten), r));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> PEDERSEN.verifyScalar(expected, ten, new HostileBigInteger(r, Q, r)));
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenBlinding.encode(new HostileBigInteger(r, Q, r)));
        assertError(CommitmentError.OUT_OF_RANGE,
                () -> PEDERSEN.verifyScalar(PEDERSEN.commitScalar(BigInteger.valueOf(256), r), new HostileBigInteger(ten, BigInteger.valueOf(256), ten), r, 8));

        // The delta: −3 on the first read, 2^200 afterwards.
        G1PedersenCommitment c = PEDERSEN.commitScalar(ten, r);
        HostileBigInteger delta = new HostileBigInteger(BigInteger.ONE.shiftLeft(200), BigInteger.valueOf(-3), BigInteger.ONE.shiftLeft(200));
        assertEquals(PEDERSEN.commitScalar(BigInteger.valueOf(7), r), c.withPublicDelta(delta, 8));
        assertEquals(1, delta.reads);
        assertError(CommitmentError.OUT_OF_RANGE,
                () -> c.withPublicDelta(new HostileBigInteger(BigInteger.ONE, BigInteger.ONE.shiftLeft(9), BigInteger.ONE), 8));
    }

    @Test
    @DisplayName("§7: the temporary octets of a subclass copy are wiped on success and on rejection")
    void subclassCopyIsWiped() {
        HostileBigInteger ok = new HostileBigInteger(BigInteger.valueOf(9), BigInteger.valueOf(9));
        PEDERSEN.commitScalar(ok, BigInteger.ONE);
        assertTrue(ok.handedOutWiped());
        HostileBigInteger rejected = new HostileBigInteger(Q, Q);
        assertError(CommitmentError.NON_CANONICAL_SCALAR, () -> G1PedersenBlinding.encode(rejected));
        assertTrue(rejected.handedOutWiped());
        HostileBigInteger delta = new HostileBigInteger(BigInteger.valueOf(-5), BigInteger.valueOf(-5));
        PEDERSEN.commitScalar(BigInteger.TEN, BigInteger.ONE).withPublicDelta(delta, 8);
        assertTrue(delta.handedOutWiped());
    }

    // ---- profile, envelope, key (commitment-profiles-v1 §9, §12) ----

    @Test
    @DisplayName("PROFILE is the registry constant: pedersen-bls12-381-g1-v1, scalar, BLS12-381 G1, 48-octet points")
    void profileConstants() {
        assertSame(CommitmentProfiles.PEDERSEN_BLS12_381_G1_V1, G1PedersenCommitment.PROFILE);
        assertSame(CommitmentProfiles.PEDERSEN_BLS12_381_G1_BYTES_V1, G1PedersenBytesCommitment.PROFILE);
        assertEquals("pedersen-bls12-381-g1-v1", G1PedersenCommitment.PROFILE.id().value());
        assertEquals("pedersen-bls12-381-g1-bytes-v1", G1PedersenBytesCommitment.PROFILE.id().value());
        assertEquals(CommitmentKind.SCALAR, G1PedersenCommitment.PROFILE.kind());
        assertEquals(CommitmentKind.BYTES, G1PedersenBytesCommitment.PROFILE.kind());
        assertEquals(CommitmentGroup.BLS12_381_G1, G1PedersenCommitment.PROFILE.group());
        assertEquals(CommitmentGroup.BLS12_381_G1, G1PedersenBytesCommitment.PROFILE.group());
        assertEquals(48, G1PedersenCommitment.PROFILE.pointEncodingLength());
        assertEquals(48, G1PedersenBytesCommitment.PROFILE.pointEncodingLength());
        assertSame(G1PedersenCommitment.PROFILE, G1PedersenCommitment.CODEC.profile());
        assertSame(G1PedersenBytesCommitment.PROFILE, G1PedersenBytesCommitment.CODEC.profile());
        assertSame(G1PedersenCommitment.class, G1PedersenCommitment.CODEC.commitmentType());
        assertSame(G1PedersenBytesCommitment.class, G1PedersenBytesCommitment.CODEC.commitmentType());
        assertEquals(0, G1PedersenCommitment.CODEC.keyContext().length);
        assertEquals(0, G1PedersenBytesCommitment.CODEC.keyContext().length);
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.ONE, BigInteger.TWO);
        assertSame(G1PedersenCommitment.PROFILE, c.profile());
        assertTrue(c.toString().contains("pedersen-bls12-381-g1-v1"));
        assertTrue(c.toString().contains(HEX.formatHex(c.toPointBytes())));
    }

    @Test
    @DisplayName("Envelope: 74 octets (scalar) and 80 octets (bytes), exact layout, round trip with the matching codec")
    void envelope() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(77), G1Pedersen.randomBlinding(RANDOM));
        byte[] scalarEnvelope = CommitmentEnvelope.encode(c);
        assertEquals(74, scalarEnvelope.length);
        assertArrayEquals(envelope("pedersen-bls12-381-g1-v1", c.toPointBytes()), scalarEnvelope);
        assertEquals(c, CommitmentEnvelope.decode(scalarEnvelope, G1PedersenCommitment.CODEC));

        G1PedersenBytesCommitment b = G1PedersenBytesCommitment.decode(c.toPointBytes());
        byte[] bytesEnvelope = CommitmentEnvelope.encode(b);
        assertEquals(80, bytesEnvelope.length);
        assertArrayEquals(envelope("pedersen-bls12-381-g1-bytes-v1", c.toPointBytes()), bytesEnvelope);
        assertEquals(b, CommitmentEnvelope.decode(bytesEnvelope, G1PedersenBytesCommitment.CODEC));

        byte[] identityEnvelope = envelope("pedersen-bls12-381-g1-v1", HEX.parseHex(C_0_0));
        assertArrayEquals(HEX.parseHex(C_0_0),
                CommitmentEnvelope.decode(identityEnvelope, G1PedersenCommitment.CODEC).toPointBytes());
    }

    @Test
    @DisplayName("Envelope: cross-profile and cross-curve substitution is PROFILE_MISMATCH; a bad point uses the strict decoder")
    void envelopeMismatch() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(78), BigInteger.ONE);
        byte[] scalarEnvelope = CommitmentEnvelope.encode(c);
        byte[] bytesEnvelope = CommitmentEnvelope.encode(G1PedersenBytesCommitment.decode(c.toPointBytes()));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(bytesEnvelope, G1PedersenCommitment.CODEC));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(scalarEnvelope, G1PedersenBytesCommitment.CODEC));

        byte[] jubjubPoint = new byte[32];
        jubjubPoint[0] = 1;
        byte[] jubjubEnvelope = envelope("pedersen-jubjub-v1", jubjubPoint);
        assertEquals(52, jubjubEnvelope.length);
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(jubjubEnvelope, G1PedersenCommitment.CODEC));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(jubjubEnvelope, G1PedersenBytesCommitment.CODEC));
        // A Jubjub identifier padded with a 48-octet point is still the wrong profile.
        byte[] jubjubPadded = envelope("pedersen-jubjub-v1", c.toPointBytes());
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentEnvelope.decode(jubjubPadded, G1PedersenCommitment.CODEC));

        assertError(CommitmentError.NOT_IN_SUBGROUP, () -> CommitmentEnvelope.decode(
                envelope("pedersen-bls12-381-g1-v1", HEX.parseHex("80" + "00".repeat(47))), G1PedersenCommitment.CODEC));
        assertError(CommitmentError.MALFORMED_ENCODING, () -> CommitmentEnvelope.decode(
                envelope("pedersen-bls12-381-g1-v1", HEX.parseHex("e0" + "00".repeat(47))), G1PedersenCommitment.CODEC));
        assertError(CommitmentError.MALFORMED_ENCODING,
                () -> CommitmentEnvelope.decode(Arrays.copyOf(scalarEnvelope, 73), G1PedersenCommitment.CODEC));
        byte[] wrongVersion = scalarEnvelope.clone();
        wrongVersion[0] = 2;
        assertError(CommitmentError.MALFORMED_ENCODING, () -> CommitmentEnvelope.decode(wrongVersion, G1PedersenCommitment.CODEC));
    }

    @Test
    @DisplayName("CommitmentKey.of with the other G1 codec is PROFILE_MISMATCH; keys differ across profiles for the same point")
    void commitmentKey() {
        G1PedersenCommitment c = PEDERSEN.commitScalar(BigInteger.valueOf(79), BigInteger.ONE);
        G1PedersenBytesCommitment b = G1PedersenBytesCommitment.decode(c.toPointBytes());
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(c, G1PedersenBytesCommitment.CODEC));
        assertError(CommitmentError.PROFILE_MISMATCH, () -> CommitmentKey.of(b, G1PedersenCommitment.CODEC));
        CommitmentKey key = CommitmentKey.of(c, G1PedersenCommitment.CODEC);
        assertEquals(key, CommitmentKey.of(G1PedersenCommitment.decode(c.toPointBytes()), G1PedersenCommitment.CODEC));
        assertNotEquals(key, CommitmentKey.of(b, G1PedersenBytesCommitment.CODEC));
        assertNotEquals(c, b);
    }

    // ---- blinding sampler (§7) ----

    @Test
    @DisplayName("randomBlinding: 64 octets read big-endian and reduced mod q; values in [0, q); buffer wiped")
    void randomBlinding() {
        for (int i = 0; i < 32; i++) {
            BigInteger r = G1Pedersen.randomBlinding(RANDOM);
            assertTrue(r.signum() >= 0 && r.compareTo(Q) < 0);
        }
        byte[] pattern = new byte[64];
        for (int i = 0; i < 64; i++) pattern[i] = (byte) (131 * i + 17);
        byte[] ones = new byte[64];
        Arrays.fill(ones, (byte) 0xff);
        for (byte[] sample : List.of(pattern, ones, new byte[64])) {
            FixedRandom random = new FixedRandom(sample, false);
            assertEquals(new BigInteger(1, sample).mod(Q), G1Pedersen.randomBlinding(random));
            assertEquals(1, random.handedOut.size());
            assertEquals(64, random.handedOut.get(0).length, "exactly 64 octets are drawn");
            assertArrayEquals(new byte[64], random.handedOut.get(0), "the sample buffer is wiped");
        }
    }

    @Test
    @DisplayName("randomBlinding: an entropy failure propagates unchanged and the partially filled buffer is wiped")
    void randomBlindingFailure() {
        FixedRandom failing = new FixedRandom(new byte[64], true);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> G1Pedersen.randomBlinding(failing));
        assertSame(FixedRandom.FAILURE, e);
        assertArrayEquals(new byte[64], failing.handedOut.get(0));
    }

    // ---- helpers ----

    private static CommitmentFormatException assertError(CommitmentError expected, Executable executable) {
        return G1PedersenDecoderTest.assertError(expected, executable, expected.toString());
    }

    private static byte[] i2osp32(BigInteger x) {
        return HEX.parseHex(String.format("%064x", x));
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] envelope(String id, byte[] point) {
        byte[] ascii = id.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[2 + ascii.length + point.length];
        out[0] = 0x01;
        out[1] = (byte) ascii.length;
        System.arraycopy(ascii, 0, out, 2, ascii.length);
        System.arraycopy(point, 0, out, 2 + ascii.length, point.length);
        return out;
    }

    /** Claims to be 1 through every observer except {@code toByteArray}, which yields {@code real}. */
    private static BigInteger liar(BigInteger real) {
        return new HostileBigInteger(BigInteger.ONE, real);
    }

    /**
     * A hostile subclass: {@code toByteArray} yields {@code reads[0]} on the first call and
     * {@code reads[1..]} afterwards, every other observer reports {@code claimed}, and the internal
     * magnitude (seen only by JDK code that reads the fields of an argument) is {@code reads[0]}.
     */
    static final class HostileBigInteger extends BigInteger {
        private final BigInteger claimed;
        private final BigInteger[] values;
        private final List<byte[]> handedOut = new ArrayList<>();
        int reads;

        HostileBigInteger(BigInteger claimed, BigInteger... values) {
            super(values[0].toByteArray());
            this.claimed = claimed;
            this.values = values.clone();
        }

        @Override
        public byte[] toByteArray() {
            byte[] out = values[Math.min(reads, values.length - 1)].toByteArray();
            reads++;
            handedOut.add(out);
            return out;
        }

        boolean handedOutWiped() {
            if (handedOut.isEmpty()) return false;
            for (byte[] b : handedOut) {
                for (byte x : b) if (x != 0) return false;
            }
            return true;
        }

        @Override public int signum() { return claimed.signum(); }
        @Override public int compareTo(BigInteger other) { return claimed.compareTo(other); }
        @Override public int bitLength() { return claimed.bitLength(); }
        @Override public int bitCount() { return claimed.bitCount(); }
        @Override public boolean testBit(int n) { return claimed.testBit(n); }
        @Override public BigInteger abs() { return claimed.abs(); }
        @Override public BigInteger negate() { return claimed.negate(); }
        @Override public BigInteger mod(BigInteger m) { return claimed.mod(m); }
        @Override public BigInteger remainder(BigInteger m) { return claimed.remainder(m); }
        @Override public BigInteger shiftRight(int n) { return claimed.shiftRight(n); }
        @Override public BigInteger shiftLeft(int n) { return claimed.shiftLeft(n); }
        @Override public BigInteger add(BigInteger v) { return claimed.add(v); }
        @Override public BigInteger subtract(BigInteger v) { return claimed.subtract(v); }
        @Override public BigInteger multiply(BigInteger v) { return claimed.multiply(v); }
        @Override public BigInteger min(BigInteger v) { return claimed.min(v); }
        @Override public BigInteger max(BigInteger v) { return claimed.max(v); }
        @Override public int intValue() { return claimed.intValue(); }
        @Override public long longValue() { return claimed.longValue(); }
        @Override public int getLowestSetBit() { return claimed.getLowestSetBit(); }
        @Override public boolean equals(Object o) { return claimed.equals(o); }
        @Override public int hashCode() { return claimed.hashCode(); }
        @Override public String toString() { return claimed.toString(); }
        @Override public String toString(int radix) { return claimed.toString(radix); }
    }

    /** Yields a fixed sample (or fails after filling it) and records every buffer it was handed. */
    static final class FixedRandom extends SecureRandom {
        static final IllegalStateException FAILURE = new IllegalStateException("entropy failure");
        private final byte[] sample;
        private final boolean fail;
        final List<byte[]> handedOut = new ArrayList<>();

        FixedRandom(byte[] sample, boolean fail) {
            this.sample = sample.clone();
            this.fail = fail;
        }

        @Override
        public void nextBytes(byte[] bytes) {
            handedOut.add(bytes);
            Arrays.fill(bytes, (byte) 0x5a);
            if (fail) throw FAILURE;
            System.arraycopy(sample, 0, bytes, 0, Math.min(sample.length, bytes.length));
        }
    }
}
