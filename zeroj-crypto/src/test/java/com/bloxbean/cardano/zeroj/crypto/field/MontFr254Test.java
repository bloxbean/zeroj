package com.bloxbean.cardano.zeroj.crypto.field;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for Montgomery-form BN254 scalar field arithmetic.
 *
 * <p>Every test cross-validates against BigInteger to ensure Montgomery
 * constants and algorithms are correct.</p>
 */
class MontFr254Test {

    static final BigInteger R = MontFr254.modulus();
    static final Random RNG = new Random(42);

    // --- Constant validation ---

    @Test
    void modulus_isCorrect() {
        assertEquals(
                new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617"),
                R);
        assertEquals(254, R.bitLength());
    }

    @Test
    void montgomeryConstants_areCorrect() {
        BigInteger mod = R;
        BigInteger R256 = BigInteger.ONE.shiftLeft(256); // R = 2^256
        BigInteger mask64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

        // INV: mod * INV ≡ -1 (mod 2^64)
        BigInteger inv = BigInteger.valueOf(MontFr254.INV).and(mask64); // treat as unsigned
        // Since Java doesn't have unsigned BigInteger from long directly, reconstruct
        inv = new BigInteger(1, longToBytes(MontFr254.INV));
        BigInteger product = mod.multiply(inv).and(mask64);
        BigInteger expected = mask64; // -1 mod 2^64 = 2^64 - 1
        assertEquals(expected, product, "INV constant: r * INV should be -1 mod 2^64");

        // RONE: R mod r = 2^256 mod r (Montgomery form of 1)
        BigInteger rModR = R256.mod(mod);
        BigInteger rone = limbsToBigInteger(MontFr254.RONE0, MontFr254.RONE1, MontFr254.RONE2, MontFr254.RONE3);
        assertEquals(rModR, rone, "RONE constant: should be 2^256 mod r");

        // R2MOD: R^2 mod r = (2^256)^2 mod r
        BigInteger r2ModR = R256.modPow(BigInteger.TWO, mod);
        BigInteger r2 = limbsToBigInteger(MontFr254.R2MOD0, MontFr254.R2MOD1, MontFr254.R2MOD2, MontFr254.R2MOD3);
        assertEquals(r2ModR, r2, "R2MOD constant: should be 2^512 mod r");

        // MOD limbs reconstruct the modulus
        BigInteger modFromLimbs = limbsToBigInteger(MontFr254.MOD0, MontFr254.MOD1, MontFr254.MOD2, MontFr254.MOD3);
        assertEquals(mod, modFromLimbs, "MOD limbs should reconstruct the modulus");
    }

    // --- Conversion round-trip ---

    @Test
    void fromBigInteger_toBigInteger_roundTrip_zero() {
        assertEquals(BigInteger.ZERO, MontFr254.ZERO.toBigInteger());
        assertEquals(BigInteger.ZERO, MontFr254.fromBigInteger(BigInteger.ZERO).toBigInteger());
    }

    @Test
    void fromBigInteger_toBigInteger_roundTrip_one() {
        assertEquals(BigInteger.ONE, MontFr254.ONE.toBigInteger());
        assertEquals(BigInteger.ONE, MontFr254.fromBigInteger(BigInteger.ONE).toBigInteger());
    }

    @Test
    void fromBigInteger_toBigInteger_roundTrip_small() {
        for (long v : new long[]{2, 3, 7, 42, 255, 65536, 1000000007L}) {
            BigInteger expected = BigInteger.valueOf(v);
            MontFr254 fe = MontFr254.fromBigInteger(expected);
            assertEquals(expected, fe.toBigInteger(), "Round-trip failed for " + v);
        }
    }

    @Test
    void fromBigInteger_toBigInteger_roundTrip_large() {
        BigInteger val = R.subtract(BigInteger.ONE); // r - 1
        assertEquals(val, MontFr254.fromBigInteger(val).toBigInteger());

        val = R.subtract(BigInteger.TWO); // r - 2
        assertEquals(val, MontFr254.fromBigInteger(val).toBigInteger());

        val = new BigInteger("123456789012345678901234567890");
        assertEquals(val, MontFr254.fromBigInteger(val).toBigInteger());
    }

    @Test
    void fromBigInteger_reducesModR() {
        // Value >= r should be reduced
        BigInteger overR = R.add(BigInteger.valueOf(42));
        assertEquals(BigInteger.valueOf(42), MontFr254.fromBigInteger(overR).toBigInteger());

        // Negative value should be reduced to positive
        BigInteger neg = BigInteger.valueOf(-1);
        assertEquals(R.subtract(BigInteger.ONE), MontFr254.fromBigInteger(neg).toBigInteger());
    }

    @Test
    void fromLong_matchesFromBigInteger() {
        for (long v : new long[]{0, 1, 2, 42, Long.MAX_VALUE}) {
            assertEquals(
                    MontFr254.fromBigInteger(BigInteger.valueOf(v)).toBigInteger(),
                    MontFr254.fromLong(v).toBigInteger(),
                    "fromLong should match fromBigInteger for " + v);
        }
    }

    // --- Addition ---

    @Test
    void add_zero() {
        var a = MontFr254.fromLong(42);
        assertEquals(a.toBigInteger(), a.add(MontFr254.ZERO).toBigInteger());
        assertEquals(a.toBigInteger(), MontFr254.ZERO.add(a).toBigInteger());
    }

    @Test
    void add_small() {
        var a = MontFr254.fromLong(3);
        var b = MontFr254.fromLong(11);
        assertEquals(BigInteger.valueOf(14), a.add(b).toBigInteger());
    }

    @Test
    void add_wrapsAroundModulus() {
        var a = MontFr254.fromBigInteger(R.subtract(BigInteger.ONE));  // r - 1
        var b = MontFr254.fromLong(2);
        assertEquals(BigInteger.ONE, a.add(b).toBigInteger(), "(r-1) + 2 should be 1");
    }

    // --- Subtraction ---

    @Test
    void sub_zero() {
        var a = MontFr254.fromLong(42);
        assertEquals(a.toBigInteger(), a.sub(MontFr254.ZERO).toBigInteger());
    }

    @Test
    void sub_small() {
        var a = MontFr254.fromLong(11);
        var b = MontFr254.fromLong(3);
        assertEquals(BigInteger.valueOf(8), a.sub(b).toBigInteger());
    }

    @Test
    void sub_underflow_wraps() {
        var a = MontFr254.fromLong(3);
        var b = MontFr254.fromLong(11);
        assertEquals(R.subtract(BigInteger.valueOf(8)), a.sub(b).toBigInteger(),
                "3 - 11 should be r - 8");
    }

    // --- Negation ---

    @Test
    void neg_zero() {
        assertEquals(BigInteger.ZERO, MontFr254.ZERO.neg().toBigInteger());
    }

    @Test
    void neg_addToOriginal_isZero() {
        var a = MontFr254.fromLong(42);
        assertTrue(a.add(a.neg()).isZero());
    }

    // --- Multiplication ---

    @Test
    void mul_byZero() {
        var a = MontFr254.fromLong(42);
        assertTrue(a.mul(MontFr254.ZERO).isZero());
    }

    @Test
    void mul_byOne() {
        var a = MontFr254.fromLong(42);
        assertEquals(a.toBigInteger(), a.mul(MontFr254.ONE).toBigInteger());
    }

    @Test
    void mul_small() {
        var a = MontFr254.fromLong(3);
        var b = MontFr254.fromLong(11);
        assertEquals(BigInteger.valueOf(33), a.mul(b).toBigInteger());
    }

    @Test
    void mul_large() {
        BigInteger aVal = new BigInteger("12345678901234567890123456789012345678");
        BigInteger bVal = new BigInteger("98765432109876543210987654321098765432");
        BigInteger expected = aVal.multiply(bVal).mod(R);

        var a = MontFr254.fromBigInteger(aVal);
        var b = MontFr254.fromBigInteger(bVal);
        assertEquals(expected, a.mul(b).toBigInteger());
    }

    @Test
    void mul_rMinusOne_squared() {
        BigInteger rMinus1 = R.subtract(BigInteger.ONE);
        BigInteger expected = rMinus1.multiply(rMinus1).mod(R); // should be 1
        assertEquals(BigInteger.ONE, expected, "(-1)^2 mod r = 1");

        var a = MontFr254.fromBigInteger(rMinus1);
        assertEquals(expected, a.mul(a).toBigInteger());
    }

    // --- Square ---

    @Test
    void square_matchesMul() {
        var a = MontFr254.fromLong(42);
        assertEquals(a.mul(a).toBigInteger(), a.square().toBigInteger());
    }

    // --- Inverse ---

    @Test
    void inverse_small() {
        var a = MontFr254.fromLong(42);
        var inv = a.inverse();
        assertTrue(a.mul(inv).isOne(), "42 * 42^{-1} should be 1");
    }

    @Test
    void inverse_ofOne() {
        assertTrue(MontFr254.ONE.inverse().isOne());
    }

    @Test
    void inverse_ofZero_throws() {
        assertThrows(ArithmeticException.class, () -> MontFr254.ZERO.inverse());
    }

    // --- Power ---

    @Test
    void pow_zero() {
        assertEquals(BigInteger.ONE, MontFr254.fromLong(42).pow(0).toBigInteger());
    }

    @Test
    void pow_one() {
        assertEquals(BigInteger.valueOf(42), MontFr254.fromLong(42).pow(1).toBigInteger());
    }

    @Test
    void pow_small() {
        BigInteger expected = BigInteger.valueOf(2).modPow(BigInteger.TEN, R);
        assertEquals(expected, MontFr254.fromLong(2).pow(10).toBigInteger());
    }

    // --- Randomized differential testing ---

    @RepeatedTest(100)
    void add_random_matchesBigInteger() {
        BigInteger aVal = randomFieldElement();
        BigInteger bVal = randomFieldElement();
        BigInteger expected = aVal.add(bVal).mod(R);

        var result = MontFr254.fromBigInteger(aVal).add(MontFr254.fromBigInteger(bVal));
        assertEquals(expected, result.toBigInteger());
    }

    @RepeatedTest(100)
    void sub_random_matchesBigInteger() {
        BigInteger aVal = randomFieldElement();
        BigInteger bVal = randomFieldElement();
        BigInteger expected = aVal.subtract(bVal).mod(R);

        var result = MontFr254.fromBigInteger(aVal).sub(MontFr254.fromBigInteger(bVal));
        assertEquals(expected, result.toBigInteger());
    }

    @RepeatedTest(100)
    void mul_random_matchesBigInteger() {
        BigInteger aVal = randomFieldElement();
        BigInteger bVal = randomFieldElement();
        BigInteger expected = aVal.multiply(bVal).mod(R);

        var result = MontFr254.fromBigInteger(aVal).mul(MontFr254.fromBigInteger(bVal));
        assertEquals(expected, result.toBigInteger());
    }

    @RepeatedTest(20)
    void inverse_random_mulToOne() {
        BigInteger aVal = randomFieldElement();
        if (aVal.signum() == 0) return; // skip zero

        var a = MontFr254.fromBigInteger(aVal);
        var inv = a.inverse();
        assertTrue(a.mul(inv).isOne(), "a * a^{-1} should be 1 for a=" + aVal);
    }

    // --- Helpers ---

    private BigInteger randomFieldElement() {
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(R);
    }

    private static BigInteger limbsToBigInteger(long l0, long l1, long l2, long l3) {
        BigInteger b = BigInteger.ZERO;
        b = b.add(new BigInteger(1, longToBytes(l3))).shiftLeft(64);
        b = b.add(new BigInteger(1, longToBytes(l2))).shiftLeft(64);
        b = b.add(new BigInteger(1, longToBytes(l1))).shiftLeft(64);
        b = b.add(new BigInteger(1, longToBytes(l0)));
        return b;
    }

    private static byte[] longToBytes(long v) {
        byte[] bytes = new byte[8];
        for (int i = 0; i < 8; i++) {
            bytes[7 - i] = (byte) (v >>> (i * 8));
        }
        return bytes;
    }
}
