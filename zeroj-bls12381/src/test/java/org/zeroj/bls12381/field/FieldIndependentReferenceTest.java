package org.zeroj.bls12381.field;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0062 D9 (field). Expected values come from outside the code under test:
 * <ul>
 *   <li>Fp6/Fp12 {@code mul}, {@code square}, {@code inv} against
 *       {@code bls12381-reference/fp12_tower_reference.py}, which models Fp12 as
 *       {@code Fp[w]/(w¹² − 2w⁶ + 2)} with schoolbook arithmetic and shares no formula with the
 *       Java tower;</li>
 *   <li>Fp/Fp2 square roots against Euler's criterion computed with {@link BigInteger#modPow};
 *       for Fp2 (p ≡ 3 mod 4) an element is a square iff its norm {@code c0² + c1²} is a square
 *       in Fp;</li>
 *   <li>{@code sgn0} against RFC 9380 §4.1, worked by hand.</li>
 * </ul>
 */
class FieldIndependentReferenceTest {
    private static final BigInteger P = Fp.P;
    private static final BigInteger HALF = P.subtract(BigInteger.ONE).shiftRight(1);

    // ---- Fp6 / Fp12 ----

    @Test
    void fp12MatchesIndependentReference() throws IOException {
        JsonNode cases = vectors().get("fp12");
        assertEquals(8, cases.size());
        for (JsonNode c : cases) {
            Fp12 a = fp12(c.get("a"));
            Fp12 b = fp12(c.get("b"));
            assertEquals(fp12(c.get("mul")), a.mul(b));
            assertEquals(fp12(c.get("square")), a.square());
            assertEquals(fp12(c.get("inv")), a.inv());
        }
    }

    @Test
    void fp6MatchesIndependentReference() throws IOException {
        JsonNode cases = vectors().get("fp6");
        assertEquals(8, cases.size());
        for (JsonNode c : cases) {
            Fp6 a = fp6(c.get("a"), 0);
            Fp6 b = fp6(c.get("b"), 0);
            assertEquals(fp6(c.get("mul"), 0), a.mul(b));
            assertEquals(fp6(c.get("square"), 0), a.square());
            assertEquals(fp6(c.get("inv"), 0), a.inv());
        }
    }

    // ---- square roots ----

    @Test
    void fpSqrtAgreesWithEulerCriterion() {
        Random random = new Random(0x0062_0001L);
        int squares = 0;
        int nonSquares = 0;
        for (int i = 0; i < 200; i++) {
            BigInteger x = new BigInteger(P.bitLength() + 8, random).mod(P);
            boolean isSquare = eulerIsSquare(x);
            var root = Fp.of(x).sqrt();
            assertEquals(isSquare, root.isPresent(), "x = " + x.toString(16));
            if (isSquare) {
                squares++;
                assertEquals(Fp.of(x), root.orElseThrow().square());
            } else {
                nonSquares++;
            }
            // The square of anything is a square and must have a root.
            Fp sq = Fp.of(x).square();
            assertEquals(sq, sq.sqrt().orElseThrow().square());
        }
        assertTrue(squares > 50 && nonSquares > 50, "both branches exercised");
    }

    @Test
    void fp2SqrtAgreesWithNormCriterion() {
        Random random = new Random(0x0062_0002L);
        int squares = 0;
        int nonSquares = 0;
        for (int i = 0; i < 200; i++) {
            BigInteger c0 = new BigInteger(P.bitLength() + 8, random).mod(P);
            BigInteger c1 = new BigInteger(P.bitLength() + 8, random).mod(P);
            Fp2 x = Fp2.of(Fp.of(c0), Fp.of(c1));
            boolean isSquare = eulerIsSquare(c0.multiply(c0).add(c1.multiply(c1)).mod(P));
            var root = x.sqrt();
            assertEquals(isSquare, root.isPresent(), "x = " + x);
            if (isSquare) {
                squares++;
                assertEquals(x, root.orElseThrow().square());
            } else {
                nonSquares++;
            }
            Fp2 sq = x.square();
            assertEquals(sq, sq.sqrt().orElseThrow().square());
        }
        assertTrue(squares > 50 && nonSquares > 50, "both branches exercised");
        // Elements of Fp embedded in Fp2 are always squares in Fp2 (p ≡ 3 mod 4).
        Fp2 minusTwo = Fp2.of(Fp.of(-2), Fp.ZERO);
        assertEquals(minusTwo, minusTwo.sqrt().orElseThrow().square());
    }

    private static boolean eulerIsSquare(BigInteger x) {
        return x.signum() == 0 || x.modPow(HALF, P).equals(BigInteger.ONE);
    }

    // ---- sgn0 (RFC 9380 §4.1) ----

    @Test
    void sgn0MatchesRfc9380Definition() {
        BigInteger pm1 = P.subtract(BigInteger.ONE); // even, because p is odd
        // m = 1: sgn0(x) = x mod 2
        assertFalse(Fp.ZERO.sgn0());
        assertTrue(Fp.ONE.sgn0());
        assertFalse(Fp.of(2).sgn0());
        assertFalse(Fp.of(pm1).sgn0());
        assertTrue(Fp.of(pm1.subtract(BigInteger.ONE)).sgn0());
        // m = 2: sgn0 = sign_0 OR (zero_0 AND sign_1)
        assertFalse(fp2(0, 0).sgn0());
        assertTrue(fp2(0, 1).sgn0());
        assertFalse(fp2(0, 2).sgn0());
        assertTrue(fp2(1, 0).sgn0());
        assertTrue(fp2(1, 2).sgn0());
        assertFalse(fp2(2, 1).sgn0(), "c0 non-zero and even: c1 is ignored");
        assertFalse(Fp2.of(Fp.ZERO, Fp.of(pm1)).sgn0());
        assertTrue(Fp2.of(Fp.ZERO, Fp.of(pm1.subtract(BigInteger.ONE))).sgn0());
    }

    private static Fp2 fp2(long c0, long c1) {
        return Fp2.of(Fp.of(c0), Fp.of(c1));
    }

    // ---- loading ----

    private static JsonNode vectors() throws IOException {
        try (InputStream in = FieldIndependentReferenceTest.class
                .getResourceAsStream("/bls12381-reference/fp12_tower_vectors.json")) {
            assertNotNull(in, "missing fp12_tower_vectors.json");
            return new ObjectMapper().readTree(in);
        }
    }

    private static Fp12 fp12(JsonNode c) {
        assertEquals(12, c.size());
        return new Fp12(fp6(c, 0), fp6(c, 6));
    }

    private static Fp6 fp6(JsonNode c, int offset) {
        return new Fp6(fp2(c, offset), fp2(c, offset + 2), fp2(c, offset + 4));
    }

    private static Fp2 fp2(JsonNode c, int offset) {
        return Fp2.of(fp(c.get(offset)), fp(c.get(offset + 1)));
    }

    private static Fp fp(JsonNode hex) {
        return Fp.of(new BigInteger(hex.asText(), 16));
    }
}
