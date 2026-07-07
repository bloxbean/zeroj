package com.bloxbean.cardano.zeroj.bls12381.field;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M1a: the flat-array {@link FpArith381} kernel must be bit-identical to the frozen
 * {@link MontFp381} oracle for mul/add/sub/sqr, over random + edge values, including the aliasing
 * cases the MSM relies on (output buffer == an input buffer).
 */
class FpArith381Test {

    private static final BigInteger P = MontFp381.modulus();
    private static final Random RND = new Random(0xF9E13816L);

    private static long[] limbs(BigInteger v) { return MontFp381.fromBigInteger(v).toLimbs(); }
    private static BigInteger rnd() { return new BigInteger(381, RND).mod(P); }

    private static final BigInteger[] EDGE = {
            BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, P.subtract(BigInteger.ONE),
            P.subtract(BigInteger.TWO), P.shiftRight(1)
    };

    private void checkAll(BigInteger a, BigInteger b) {
        long[] la = limbs(a), lb = limbs(b);
        MontFp381 ma = MontFp381.fromBigInteger(a), mb = MontFp381.fromBigInteger(b);

        long[] out = new long[6];
        FpArith381.mul(out, 0, la, 0, lb, 0);
        assertArrayEquals(ma.mul(mb).toLimbs(), out, "mul " + a + " * " + b);
        FpArith381.add(out, 0, la, 0, lb, 0);
        assertArrayEquals(ma.add(mb).toLimbs(), out, "add " + a + " + " + b);
        FpArith381.sub(out, 0, la, 0, lb, 0);
        assertArrayEquals(ma.sub(mb).toLimbs(), out, "sub " + a + " - " + b);
        FpArith381.sqr(out, 0, la, 0);
        assertArrayEquals(ma.mul(ma).toLimbs(), out, "sqr " + a);
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
            MontFp381 ma = MontFp381.fromBigInteger(a), mb = MontFp381.fromBigInteger(b);

            // out aliases a
            long[] x = limbs(a), y = limbs(b);
            FpArith381.mul(x, 0, x, 0, y, 0);
            assertArrayEquals(ma.mul(mb).toLimbs(), x, "mul aliasing out==a");

            // out aliases b
            x = limbs(a); y = limbs(b);
            FpArith381.add(y, 0, x, 0, y, 0);
            assertArrayEquals(ma.add(mb).toLimbs(), y, "add aliasing out==b");

            // sqr in place (out==a==b)
            x = limbs(a);
            FpArith381.sqr(x, 0, x, 0);
            assertArrayEquals(ma.mul(ma).toLimbs(), x, "sqr in place");
        }
    }

    @Test
    void offsetsRespected() {
        BigInteger a = rnd(), b = rnd();
        long[] buf = new long[24];
        long[] la = limbs(a), lb = limbs(b);
        System.arraycopy(la, 0, buf, 6, 6);
        System.arraycopy(lb, 0, buf, 12, 6);
        FpArith381.mul(buf, 18, buf, 6, buf, 12);
        long[] out = new long[6];
        System.arraycopy(buf, 18, out, 0, 6);
        assertArrayEquals(MontFp381.fromBigInteger(a).mul(MontFp381.fromBigInteger(b)).toLimbs(), out,
                "mul must honor arbitrary offsets");
    }
}
