package com.bloxbean.cardano.zeroj.crypto.field;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class MontFp254Test {

    static final BigInteger P = MontFp254.modulus();
    static final Random RNG = new Random(123);

    @Test
    void modulus_isCorrect() {
        assertEquals(
                new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583"),
                P);
        assertEquals(254, P.bitLength());
        assertTrue(P.isProbablePrime(40));
    }

    @Test
    void roundTrip_small() {
        for (long v : new long[]{0, 1, 2, 3, 42, 255, 65536, 1000000007L}) {
            assertEquals(BigInteger.valueOf(v), MontFp254.fromLong(v).toBigInteger());
        }
    }

    @Test
    void roundTrip_large() {
        BigInteger val = P.subtract(BigInteger.ONE);
        assertEquals(val, MontFp254.fromBigInteger(val).toBigInteger());
        val = new BigInteger("123456789012345678901234567890");
        assertEquals(val, MontFp254.fromBigInteger(val).toBigInteger());
    }

    @Test
    void add_wrapsModulus() {
        var a = MontFp254.fromBigInteger(P.subtract(BigInteger.ONE));
        var b = MontFp254.fromLong(2);
        assertEquals(BigInteger.ONE, a.add(b).toBigInteger());
    }

    @Test
    void sub_underflow() {
        var a = MontFp254.fromLong(3);
        var b = MontFp254.fromLong(11);
        assertEquals(P.subtract(BigInteger.valueOf(8)), a.sub(b).toBigInteger());
    }

    @Test
    void mul_small() {
        assertEquals(BigInteger.valueOf(33), MontFp254.fromLong(3).mul(MontFp254.fromLong(11)).toBigInteger());
    }

    @Test
    void mul_rMinusOne_squared() {
        var a = MontFp254.fromBigInteger(P.subtract(BigInteger.ONE));
        assertEquals(BigInteger.ONE, a.mul(a).toBigInteger(), "(-1)^2 = 1");
    }

    @Test
    void inverse_roundTrip() {
        var a = MontFp254.fromLong(42);
        assertTrue(a.mul(a.inverse()).isOne());
    }

    @RepeatedTest(100)
    void mul_random_matchesBigInteger() {
        BigInteger a = randomFp(), b = randomFp();
        assertEquals(a.multiply(b).mod(P), MontFp254.fromBigInteger(a).mul(MontFp254.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(100)
    void add_random_matchesBigInteger() {
        BigInteger a = randomFp(), b = randomFp();
        assertEquals(a.add(b).mod(P), MontFp254.fromBigInteger(a).add(MontFp254.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(100)
    void sub_random_matchesBigInteger() {
        BigInteger a = randomFp(), b = randomFp();
        assertEquals(a.subtract(b).mod(P), MontFp254.fromBigInteger(a).sub(MontFp254.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(20)
    void inverse_random() {
        BigInteger a = randomFp();
        if (a.signum() == 0) return;
        var fe = MontFp254.fromBigInteger(a);
        assertTrue(fe.mul(fe.inverse()).isOne());
    }

    private BigInteger randomFp() {
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(P);
    }
}
