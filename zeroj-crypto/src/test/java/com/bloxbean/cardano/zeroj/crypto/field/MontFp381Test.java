package com.bloxbean.cardano.zeroj.crypto.field;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class MontFp381Test {

    static final BigInteger P = MontFp381.modulus();
    static final Random RNG = new Random(381);

    @Test
    void modulus_isCorrect() {
        assertEquals(new BigInteger(
                "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16), P);
        assertEquals(381, P.bitLength());
        assertTrue(P.isProbablePrime(40));
    }

    @Test
    void roundTrip_small() {
        for (long v : new long[]{0, 1, 2, 3, 42, 255, 65536, 1000000007L}) {
            assertEquals(BigInteger.valueOf(v), MontFp381.fromLong(v).toBigInteger());
        }
    }

    @Test
    void roundTrip_large() {
        BigInteger val = P.subtract(BigInteger.ONE);
        assertEquals(val, MontFp381.fromBigInteger(val).toBigInteger());
        val = new BigInteger("123456789012345678901234567890123456789012345678901234567890");
        assertEquals(val, MontFp381.fromBigInteger(val).toBigInteger());
    }

    @Test
    void add_wrapsModulus() {
        var a = MontFp381.fromBigInteger(P.subtract(BigInteger.ONE));
        var b = MontFp381.fromLong(2);
        assertEquals(BigInteger.ONE, a.add(b).toBigInteger());
    }

    @Test
    void sub_underflow() {
        var a = MontFp381.fromLong(3);
        var b = MontFp381.fromLong(11);
        assertEquals(P.subtract(BigInteger.valueOf(8)), a.sub(b).toBigInteger());
    }

    @Test
    void mul_small() {
        assertEquals(BigInteger.valueOf(33), MontFp381.fromLong(3).mul(MontFp381.fromLong(11)).toBigInteger());
    }

    @Test
    void mul_pMinusOne_squared() {
        var a = MontFp381.fromBigInteger(P.subtract(BigInteger.ONE));
        assertEquals(BigInteger.ONE, a.mul(a).toBigInteger(), "(-1)^2 = 1");
    }

    @Test
    void inverse_roundTrip() {
        var a = MontFp381.fromLong(42);
        assertTrue(a.mul(a.inverse()).isOne());
    }

    @RepeatedTest(200)
    void mul_random_matchesBigInteger() {
        BigInteger a = randomFp(), b = randomFp();
        assertEquals(a.multiply(b).mod(P), MontFp381.fromBigInteger(a).mul(MontFp381.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(200)
    void add_random_matchesBigInteger() {
        BigInteger a = randomFp(), b = randomFp();
        assertEquals(a.add(b).mod(P), MontFp381.fromBigInteger(a).add(MontFp381.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(200)
    void sub_random_matchesBigInteger() {
        BigInteger a = randomFp(), b = randomFp();
        assertEquals(a.subtract(b).mod(P), MontFp381.fromBigInteger(a).sub(MontFp381.fromBigInteger(b)).toBigInteger());
    }

    @RepeatedTest(50)
    void inverse_random() {
        BigInteger a = randomFp();
        if (a.signum() == 0) return;
        var fe = MontFp381.fromBigInteger(a);
        assertTrue(fe.mul(fe.inverse()).isOne());
    }

    @Test
    void inverse_zero_throws() {
        assertThrows(ArithmeticException.class, () -> MontFp381.ZERO.inverse());
    }

    @Test
    void boundary_modulusWraps() {
        assertTrue(MontFp381.fromBigInteger(P).isZero());
        assertTrue(MontFp381.fromBigInteger(P.add(BigInteger.ONE)).isOne());
    }

    @RepeatedTest(100)
    void square_random_matchesMul() {
        BigInteger a = randomFp();
        var fe = MontFp381.fromBigInteger(a);
        assertEquals(fe.mul(fe).toBigInteger(), fe.square().toBigInteger());
    }

    @Test
    void crossValidate_withVerifierFp() {
        // Cross-validate against the verifier's BigInteger-based Fp
        var vFp = com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.Fp.class;
        BigInteger a = new BigInteger("123456789012345678901234567890123456789012345678901234567890");
        BigInteger b = new BigInteger("987654321098765432109876543210987654321098765432109876543210");

        var montA = MontFp381.fromBigInteger(a);
        var montB = MontFp381.fromBigInteger(b);

        var verA = new com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.Fp(a);
        var verB = new com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field.Fp(b);

        assertEquals(verA.mul(verB).value(), montA.mul(montB).toBigInteger(), "mul cross-validate");
        assertEquals(verA.add(verB).value(), montA.add(montB).toBigInteger(), "add cross-validate");
        assertEquals(verA.sub(verB).value(), montA.sub(montB).toBigInteger(), "sub cross-validate");
        assertEquals(verA.inv().value(), montA.inverse().toBigInteger(), "inv cross-validate");
    }

    private BigInteger randomFp() {
        byte[] bytes = new byte[48];
        RNG.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(P);
    }
}
