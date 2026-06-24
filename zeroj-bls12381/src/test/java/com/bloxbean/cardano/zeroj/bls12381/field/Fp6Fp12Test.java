package com.bloxbean.cardano.zeroj.bls12381.field;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Fp6Fp12Test {

    @Test
    void fp6_squareMatchesMul() {
        Fp6 a = fp6(42, 7, 3, 5, 11, 13);

        assertEquals(a.mul(a), a.square());
    }

    @Test
    void fp6_inverseRoundTrip() {
        Fp6 a = fp6(42, 7, 3, 5, 11, 13);

        assertEquals(Fp6.ONE, a.mul(a.inv()));
    }

    @Test
    void fp12_squareMatchesMul() {
        Fp12 a = fp12(
                fp6(42, 7, 3, 5, 11, 13),
                fp6(17, 19, 23, 29, 31, 37));

        assertEquals(a.mul(a), a.square());
    }

    @Test
    void fp12_inverseRoundTrip() {
        Fp12 a = fp12(
                fp6(42, 7, 3, 5, 11, 13),
                fp6(17, 19, 23, 29, 31, 37));

        assertTrue(a.mul(a.inv()).isOne());
    }

    @Test
    void fp12_distributesOverAddition() {
        Fp12 a = fp12(
                fp6(42, 7, 3, 5, 11, 13),
                fp6(17, 19, 23, 29, 31, 37));
        Fp12 b = fp12(
                fp6(41, 43, 47, 53, 59, 61),
                fp6(67, 71, 73, 79, 83, 89));
        Fp12 c = fp12(
                fp6(97, 101, 103, 107, 109, 113),
                fp6(127, 131, 137, 139, 149, 151));

        assertEquals(a.mul(b).add(a.mul(c)), a.mul(b.add(c)));
    }

    private static Fp12 fp12(Fp6 c0, Fp6 c1) {
        return new Fp12(c0, c1);
    }

    private static Fp6 fp6(long c00, long c01, long c10, long c11, long c20, long c21) {
        return new Fp6(fp2(c00, c01), fp2(c10, c11), fp2(c20, c21));
    }

    private static Fp2 fp2(long c0, long c1) {
        return Fp2.of(Fp.of(c0), Fp.of(c1));
    }
}
