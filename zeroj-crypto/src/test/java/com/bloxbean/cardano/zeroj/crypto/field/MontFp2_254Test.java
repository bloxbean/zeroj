package com.bloxbean.cardano.zeroj.crypto.field;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class MontFp2_254Test {

    static final BigInteger P = MontFp254.modulus();
    static final Random RNG = new Random(77);

    @Test
    void add_commutative() {
        var a = MontFp2_254.of(3, 7);
        var b = MontFp2_254.of(11, 5);
        var ab = a.add(b);
        var ba = b.add(a);
        assertEquals(ab.reBigInt(), ba.reBigInt());
        assertEquals(ab.imBigInt(), ba.imBigInt());
    }

    @Test
    void mul_identity() {
        var a = MontFp2_254.of(42, 17);
        var prod = a.mul(MontFp2_254.ONE);
        assertEquals(BigInteger.valueOf(42), prod.reBigInt());
        assertEquals(BigInteger.valueOf(17), prod.imBigInt());
    }

    @Test
    void mul_byU() {
        // (0 + 1*u) * (a + b*u) = -b + a*u  (since u^2 = -1)
        var u = MontFp2_254.of(0, 1);
        var a = MontFp2_254.of(3, 7);
        var result = u.mul(a);
        assertEquals(P.subtract(BigInteger.valueOf(7)), result.reBigInt(), "real = -7");
        assertEquals(BigInteger.valueOf(3), result.imBigInt(), "imag = 3");
    }

    @Test
    void mul_small() {
        // (2 + 3u)(4 + 5u) = (8 - 15) + (10 + 12)u = -7 + 22u
        var a = MontFp2_254.of(2, 3);
        var b = MontFp2_254.of(4, 5);
        var c = a.mul(b);
        assertEquals(P.subtract(BigInteger.valueOf(7)), c.reBigInt());
        assertEquals(BigInteger.valueOf(22), c.imBigInt());
    }

    @Test
    void square_matchesMul() {
        var a = MontFp2_254.of(42, 17);
        var sq = a.square();
        var mulSelf = a.mul(a);
        assertEquals(sq.reBigInt(), mulSelf.reBigInt());
        assertEquals(sq.imBigInt(), mulSelf.imBigInt());
    }

    @Test
    void inverse_roundTrip() {
        var a = MontFp2_254.of(42, 17);
        var inv = a.inverse();
        var prod = a.mul(inv);
        assertTrue(prod.isOne(), "a * a^{-1} should be 1");
    }

    @Test
    void conjugate_mulIsNorm() {
        var a = MontFp2_254.of(42, 17);
        var prod = a.mul(a.conjugate());
        assertTrue(prod.im().isZero(), "a * conj(a) should be real");
        assertEquals(a.norm().toBigInteger(), prod.reBigInt());
    }

    @RepeatedTest(50)
    void mul_random_matchesBigInteger() {
        BigInteger a_re = randomFp(), a_im = randomFp();
        BigInteger b_re = randomFp(), b_im = randomFp();

        // Expected: (a_re + a_im*u)(b_re + b_im*u) = (a_re*b_re - a_im*b_im) + (a_re*b_im + a_im*b_re)*u
        BigInteger expRe = a_re.multiply(b_re).subtract(a_im.multiply(b_im)).mod(P);
        BigInteger expIm = a_re.multiply(b_im).add(a_im.multiply(b_re)).mod(P);

        var result = MontFp2_254.of(a_re, a_im).mul(MontFp2_254.of(b_re, b_im));
        assertEquals(expRe, result.reBigInt());
        assertEquals(expIm, result.imBigInt());
    }

    @RepeatedTest(20)
    void inverse_random_mulToOne() {
        BigInteger re = randomFp(), im = randomFp();
        if (re.signum() == 0 && im.signum() == 0) return;
        var a = MontFp2_254.of(re, im);
        assertTrue(a.mul(a.inverse()).isOne());
    }

    private BigInteger randomFp() {
        byte[] bytes = new byte[32];
        RNG.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(P);
    }
}
