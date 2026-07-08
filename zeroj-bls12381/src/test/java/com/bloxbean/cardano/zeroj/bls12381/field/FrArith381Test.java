package com.bloxbean.cardano.zeroj.bls12381.field;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * ADR-0029 M2c: the flat {@link FrArith381} kernel must be bit-identical to the frozen
 * {@link MontFr381} oracle for mul/add/sub/sqr, over random + edge values, including aliasing.
 */
class FrArith381Test {

    private static final BigInteger R = MontFr381.modulus();
    private static final Random RND = new Random(0xF12A11L);

    private static long[] limbs(MontFr381 m) { return new long[]{m.l0, m.l1, m.l2, m.l3}; }
    private static long[] montLimbs(BigInteger v) { return limbs(MontFr381.fromBigInteger(v)); }
    private static BigInteger rnd() { return new BigInteger(255, RND).mod(R); }

    private static final BigInteger[] EDGE = {
            BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, R.subtract(BigInteger.ONE),
            R.subtract(BigInteger.TWO), R.shiftRight(1)
    };

    private void checkAll(BigInteger a, BigInteger b) {
        long[] la = montLimbs(a), lb = montLimbs(b);
        MontFr381 ma = MontFr381.fromBigInteger(a), mb = MontFr381.fromBigInteger(b);
        long[] out = new long[4];

        FrArith381.mul(out, 0, la, 0, lb, 0);
        assertArrayEquals(limbs(ma.mul(mb)), out, "mul " + a + "*" + b);
        FrArith381.add(out, 0, la, 0, lb, 0);
        assertArrayEquals(limbs(ma.add(mb)), out, "add " + a + "+" + b);
        FrArith381.sub(out, 0, la, 0, lb, 0);
        assertArrayEquals(limbs(ma.sub(mb)), out, "sub " + a + "-" + b);
        FrArith381.sqr(out, 0, la, 0);
        assertArrayEquals(limbs(ma.mul(ma)), out, "sqr " + a);
    }

    @Test
    void matchesOracle_edgeAndRandom() {
        for (BigInteger a : EDGE) for (BigInteger b : EDGE) checkAll(a, b);
        for (int t = 0; t < 400; t++) checkAll(rnd(), rnd());
    }

    @Test
    void aliasing_outputEqualsInput() {
        for (int t = 0; t < 200; t++) {
            BigInteger a = rnd(), b = rnd();
            MontFr381 ma = MontFr381.fromBigInteger(a), mb = MontFr381.fromBigInteger(b);

            long[] x = montLimbs(a), y = montLimbs(b);
            FrArith381.mul(x, 0, x, 0, y, 0);
            assertArrayEquals(limbs(ma.mul(mb)), x, "mul aliasing");

            x = montLimbs(a); y = montLimbs(b);
            FrArith381.add(y, 0, x, 0, y, 0);
            assertArrayEquals(limbs(ma.add(mb)), y, "add aliasing");

            x = montLimbs(a);
            FrArith381.sqr(x, 0, x, 0);
            assertArrayEquals(limbs(ma.mul(ma)), x, "sqr in place");
        }
    }
}
