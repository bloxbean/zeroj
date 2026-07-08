package com.bloxbean.cardano.zeroj.bls12381.ec;

import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M1b: {@link JacobianArith381} flat point ops must be curve-equivalent to
 * {@link JacobianG1BLS381} (compared via affine coordinates, which are canonical). Covers random
 * points with non-trivial Z, the special cases (P+(−P)→∞, P+P→double, ∞ identities), and the
 * output-aliases-input case the MSM relies on.
 */
class JacobianArith381Test {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0x0A0B0C0DL);

    private final long[] s = new long[JacobianArith381.SCRATCH_LONGS];

    private static JacobianG1BLS381 pt(BigInteger k) { return JacobianG1BLS381.GENERATOR.scalarMul(k.mod(R)); }
    private static BigInteger rndScalar() { return new BigInteger(255, RND).mod(R); }

    /** Load a (non-infinity) oracle point into flat affine form (Z=1). */
    private static long[] loadAffine(JacobianG1BLS381 j) {
        var aff = j.toAffine();
        long[] p = new long[JacobianArith381.POINT_LONGS];
        System.arraycopy(aff.x().toLimbs(), 0, p, 0, 6);
        System.arraycopy(aff.y().toLimbs(), 0, p, 6, 6);
        System.arraycopy(MontFp381.ONE.toLimbs(), 0, p, 12, 6);
        return p;
    }

    /** Flat point → affine [x,y] as BigInteger, or null for infinity. */
    private static BigInteger[] flatAffine(long[] p, int off) {
        MontFp381 z = MontFp381.fromMontLimbs(p[off+12], p[off+13], p[off+14], p[off+15], p[off+16], p[off+17]);
        if (z.isZero()) return null;
        MontFp381 x = MontFp381.fromMontLimbs(p[off], p[off+1], p[off+2], p[off+3], p[off+4], p[off+5]);
        MontFp381 y = MontFp381.fromMontLimbs(p[off+6], p[off+7], p[off+8], p[off+9], p[off+10], p[off+11]);
        MontFp381 zi = z.inverse(), zi2 = zi.square(), zi3 = zi2.mul(zi);
        return new BigInteger[]{ x.mul(zi2).toBigInteger(), y.mul(zi3).toBigInteger() };
    }

    private static BigInteger[] oracleAffine(JacobianG1BLS381 j) {
        if (j.isInfinity()) return null;
        var a = j.toAffine();
        return new BigInteger[]{ a.x().toBigInteger(), a.y().toBigInteger() };
    }

    private static void assertSame(String msg, JacobianG1BLS381 oracle, long[] flat, int off) {
        assertArrayEquals(oracleAffine(oracle), flatAffine(flat, off), msg);
    }

    /** A flat point with non-trivial Z (double an affine-form point). */
    private long[] projective(JacobianG1BLS381 j) {
        long[] p = loadAffine(j), o = new long[JacobianArith381.POINT_LONGS];
        JacobianArith381.dbl(o, 0, p, 0, s);
        return o; // ~ j.doublePoint(), with Z != 1
    }

    @Test
    void dbl_matchesOracle() {
        for (int t = 0; t < 60; t++) {
            JacobianG1BLS381 j = pt(rndScalar());
            long[] o = new long[18];
            JacobianArith381.dbl(o, 0, loadAffine(j), 0, s);
            assertSame("dbl", j.doublePoint(), o, 0);
        }
    }

    @Test
    void add_matchesOracle_affineAndProjectiveInputs() {
        for (int t = 0; t < 60; t++) {
            JacobianG1BLS381 j1 = pt(rndScalar()), j2 = pt(rndScalar());
            long[] o = new long[18];
            // affine-form inputs (Z=1)
            JacobianArith381.add(o, 0, loadAffine(j1), 0, loadAffine(j2), 0, s);
            assertSame("add(affine,affine)", j1.add(j2), o, 0);
            // projective input (Z!=1): j1.double() + j2
            JacobianArith381.add(o, 0, projective(j1), 0, loadAffine(j2), 0, s);
            assertSame("add(projective,affine)", j1.doublePoint().add(j2), o, 0);
        }
    }

    @Test
    void addAffine_matchesOracle() {
        for (int t = 0; t < 60; t++) {
            JacobianG1BLS381 j1 = pt(rndScalar()), j2 = pt(rndScalar());
            var aff2 = j2.toAffine();
            long[] o = new long[18];
            long[] acc = projective(j1); // Z != 1
            JacobianArith381.addAffine(o, 0, acc, 0, aff2.x().toLimbs(), 0, aff2.y().toLimbs(), 0, s);
            assertSame("addAffine", j1.doublePoint().addAffine(aff2.x(), aff2.y()), o, 0);
        }
    }

    @Test
    void specialCases() {
        JacobianG1BLS381 j = pt(BigInteger.valueOf(12345));
        long[] P = loadAffine(j), o = new long[18];
        long[] inf = new long[18]; JacobianArith381.setInfinity(inf, 0);

        // P + (-P) = infinity
        JacobianArith381.add(o, 0, P, 0, loadAffine(j.negate()), 0, s);
        assertNull(flatAffine(o, 0), "P + (-P) must be infinity");
        // P + P routes through double
        JacobianArith381.add(o, 0, P, 0, P, 0, s);
        assertSame("P+P == 2P", j.doublePoint(), o, 0);
        // identities
        JacobianArith381.add(o, 0, inf, 0, P, 0, s);
        assertSame("inf + P == P", j, o, 0);
        JacobianArith381.add(o, 0, P, 0, inf, 0, s);
        assertSame("P + inf == P", j, o, 0);
        JacobianArith381.dbl(o, 0, inf, 0, s);
        assertNull(flatAffine(o, 0), "dbl(inf) == inf");
    }

    @Test
    void aliasing_outEqualsInput() {
        for (int t = 0; t < 40; t++) {
            JacobianG1BLS381 j1 = pt(rndScalar()), j2 = pt(rndScalar());
            long[] a = loadAffine(j1), b = loadAffine(j2);
            long[] aCopy = Arrays.copyOf(a, 18);
            JacobianArith381.add(a, 0, a, 0, b, 0, s); // out == a
            assertSame("add out==a", j1.add(j2), a, 0);
            JacobianArith381.dbl(aCopy, 0, aCopy, 0, s); // out == in
            assertSame("dbl out==in", j1.doublePoint(), aCopy, 0);
        }
    }
}
