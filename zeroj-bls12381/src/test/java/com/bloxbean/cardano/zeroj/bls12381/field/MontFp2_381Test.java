package com.bloxbean.cardano.zeroj.bls12381.field;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.RepeatedTest;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class MontFp2_381Test {

    static final BigInteger P = MontFp381.modulus();
    static final Random RNG = new Random(383);

    @Test
    void one_mul_one_isOne() {
        assertTrue(MontFp2_381.ONE.mul(MontFp2_381.ONE).isOne());
    }

    @Test
    void zero_add_zero_isZero() {
        assertTrue(MontFp2_381.ZERO.add(MontFp2_381.ZERO).isZero());
    }

    @Test
    void mul_by_zero_isZero() {
        var a = MontFp2_381.of(42, 7);
        assertTrue(a.mul(MontFp2_381.ZERO).isZero());
    }

    @Test
    void mul_by_one_isIdentity() {
        var a = MontFp2_381.of(42, 7);
        assertEquals(a, a.mul(MontFp2_381.ONE));
    }

    @Test
    void inverse_roundTrip() {
        var a = MontFp2_381.of(42, 7);
        assertTrue(a.mul(a.inverse()).isOne());
    }

    @Test
    void conjugate_selfMul_hasZeroIm() {
        var a = MontFp2_381.of(42, 7);
        var product = a.mul(a.conjugate());
        assertTrue(product.im().isZero(), "a * conj(a) should have zero imaginary part");
    }

    @RepeatedTest(100)
    void mul_random_matchesBigIntegerFp2() {
        BigInteger a0 = randomFp(), a1 = randomFp();
        BigInteger b0 = randomFp(), b1 = randomFp();

        var montA = MontFp2_381.of(a0, a1);
        var montB = MontFp2_381.of(b0, b1);
        var result = montA.mul(montB);

        // Manual Fp2 mul: (a0+a1*u)(b0+b1*u) = (a0*b0 - a1*b1) + (a0*b1 + a1*b0)*u
        BigInteger expectedRe = a0.multiply(b0).subtract(a1.multiply(b1)).mod(P);
        BigInteger expectedIm = a0.multiply(b1).add(a1.multiply(b0)).mod(P);

        assertEquals(expectedRe, result.reBigInt());
        assertEquals(expectedIm, result.imBigInt());
    }

    @RepeatedTest(100)
    void square_matchesMul() {
        BigInteger a0 = randomFp(), a1 = randomFp();
        var a = MontFp2_381.of(a0, a1);
        var sq = a.square();
        var mulSelf = a.mul(a);
        assertEquals(mulSelf.reBigInt(), sq.reBigInt());
        assertEquals(mulSelf.imBigInt(), sq.imBigInt());
    }

    @RepeatedTest(50)
    void inverse_random() {
        BigInteger a0 = randomFp(), a1 = randomFp();
        if (a0.signum() == 0 && a1.signum() == 0) return;
        var a = MontFp2_381.of(a0, a1);
        assertTrue(a.mul(a.inverse()).isOne());
    }

    @Test
    void crossValidate_withVerifierFp2() {
        BigInteger a0 = new BigInteger("111222333444555666777888999000111222333444555666777888999");
        BigInteger a1 = new BigInteger("999888777666555444333222111000999888777666555444333222111");
        BigInteger b0 = new BigInteger("123456789012345678901234567890123456789012345678901234567890");
        BigInteger b1 = new BigInteger("987654321098765432109876543210987654321098765432109876543210");

        var montA = MontFp2_381.of(a0, a1);
        var montB = MontFp2_381.of(b0, b1);

        var verFp = com.bloxbean.cardano.zeroj.bls12381.field.Fp.class;
        var verA = com.bloxbean.cardano.zeroj.bls12381.field.Fp2.of(
                com.bloxbean.cardano.zeroj.bls12381.field.Fp.of(a0),
                com.bloxbean.cardano.zeroj.bls12381.field.Fp.of(a1));
        var verB = com.bloxbean.cardano.zeroj.bls12381.field.Fp2.of(
                com.bloxbean.cardano.zeroj.bls12381.field.Fp.of(b0),
                com.bloxbean.cardano.zeroj.bls12381.field.Fp.of(b1));

        var montResult = montA.mul(montB);
        var verResult = verA.mul(verB);

        assertEquals(verResult.c0().value(), montResult.reBigInt(), "Fp2 mul c0 cross-validate");
        assertEquals(verResult.c1().value(), montResult.imBigInt(), "Fp2 mul c1 cross-validate");
    }

    private BigInteger randomFp() {
        byte[] bytes = new byte[48];
        RNG.nextBytes(bytes);
        return new BigInteger(1, bytes).mod(P);
    }
}
