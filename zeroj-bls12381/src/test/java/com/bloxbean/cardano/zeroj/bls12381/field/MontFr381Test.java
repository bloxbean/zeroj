package com.bloxbean.cardano.zeroj.bls12381.field;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class MontFr381Test {

    static final BigInteger R = MontFr381.modulus();
    static final Random RNG = new Random(382);

    @Test
    void modulus_isCorrect() {
        assertEquals(new BigInteger(
                "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16), R);
        assertEquals(255, R.bitLength());
        assertTrue(R.isProbablePrime(40));
    }

    @Test
    void twoAdicity_is32() {
        BigInteger rm1 = R.subtract(BigInteger.ONE);
        int adicity = 0;
        while (rm1.testBit(adicity) == false) adicity++;
        assertEquals(32, adicity, "BLS12-381 Fr 2-adicity must be 32");
    }

    @Test
    void roundTrip_small() {
        for (long v : new long[]{0, 1, 2, 3, 42, 255, 65536, 1000000007L}) {
            assertEquals(BigInteger.valueOf(v), MontFr381.fromLong(v).toBigInteger());
        }
    }

    @Test
    void roundTrip_large() {
        BigInteger val = R.subtract(BigInteger.ONE);
        assertEquals(val, MontFr381.fromBigInteger(val).toBigInteger());
        val = new BigInteger("123456789012345678901234567890");
        assertEquals(val, MontFr381.fromBigInteger(val).toBigInteger());
    }

    @Test
    void add_wrapsModulus() {
        var a = MontFr381.fromBigInteger(R.subtract(BigInteger.ONE));
        var b = MontFr381.fromLong(2);
        assertEquals(BigInteger.ONE, a.add(b).toBigInteger());
    }

    @Test
    void sub_underflow() {
        var a = MontFr381.fromLong(3);
        var b = MontFr381.fromLong(11);
        assertEquals(R.subtract(BigInteger.valueOf(8)), a.sub(b).toBigInteger());
    }

    @Test
    void mul_small() {
        assertEquals(BigInteger.valueOf(33), MontFr381.fromLong(3).mul(MontFr381.fromLong(11)).toBigInteger());
    }

    @Test
    void mul_rMinusOne_squared() {
        var a = MontFr381.fromBigInteger(R.subtract(BigInteger.ONE));
        assertEquals(BigInteger.ONE, a.mul(a).toBigInteger(), "(-1)^2 = 1");
    }

    @Test
    void inverse_roundTrip() {
        var a = MontFr381.fromLong(42);
        assertTrue(a.mul(a.inverse()).isOne());
    }

    @RepeatedTest(200)
    void mul_random_matchesBigInteger() {
        BigInteger a = randomFr(), b = randomFr();
        assertEquals(a.multiply(b).mod(R), MontFr381.fromBigInteger(a).mul(MontFr381.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(200)
    void add_random_matchesBigInteger() {
        BigInteger a = randomFr(), b = randomFr();
        assertEquals(a.add(b).mod(R), MontFr381.fromBigInteger(a).add(MontFr381.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(200)
    void sub_random_matchesBigInteger() {
        BigInteger a = randomFr(), b = randomFr();
        assertEquals(a.subtract(b).mod(R), MontFr381.fromBigInteger(a).sub(MontFr381.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(50)
    void inverse_random() {
        BigInteger a = randomFr();
        if (a.signum() == 0) return;
        var fe = MontFr381.fromBigInteger(a);
        assertTrue(fe.mul(fe.inverse()).isOne());
    }

    @Test
    void inverse_zero_throws() {
        assertThrows(ArithmeticException.class, () -> MontFr381.ZERO.inverse());
    }

    @Test
    void pow_zero_isOne() {
        var a = MontFr381.fromLong(42);
        assertTrue(a.pow(0).isOne(), "x^0 must be 1");
    }

    @Test
    void pow_one_isIdentity() {
        var a = MontFr381.fromLong(42);
        assertEquals(BigInteger.valueOf(42), a.pow(1).toBigInteger());
    }

    @Test
    void pow_small_matchesBigInteger() {
        BigInteger base = BigInteger.valueOf(7);
        for (long exp = 2; exp <= 20; exp++) {
            assertEquals(
                    base.modPow(BigInteger.valueOf(exp), R),
                    MontFr381.fromLong(7).pow(exp).toBigInteger(),
                    "7^" + exp + " mod r");
        }
    }

    @RepeatedTest(50)
    void pow_random_matchesBigInteger() {
        BigInteger base = randomFr();
        if (base.signum() == 0) return;
        long exp = Math.abs(RNG.nextLong()) % 1000;
        assertEquals(
                base.modPow(BigInteger.valueOf(exp), R),
                MontFr381.fromBigInteger(base).pow(exp).toBigInteger());
    }

    @Test
    void boundary_pMinusOne_squared_isOne() {
        var pMinus1 = MontFr381.fromBigInteger(R.subtract(BigInteger.ONE));
        assertEquals(BigInteger.ONE, pMinus1.square().toBigInteger(), "(-1)^2 = 1");
    }

    @Test
    void boundary_modulusWraps() {
        // fromBigInteger(r) should give ZERO
        assertTrue(MontFr381.fromBigInteger(R).isZero());
        assertTrue(MontFr381.fromBigInteger(R.add(BigInteger.ONE)).isOne());
    }

    private BigInteger randomFr() {
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(R);
    }
}
