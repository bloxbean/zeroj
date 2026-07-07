package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M1c: the flat {@link PippengerFlatBLS381} MSM must be curve-equivalent to the object-based
 * {@link PippengerBLS381#msm} oracle across window sizes, zero scalars, and infinity points.
 */
class PippengerFlatBLS381Test {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0x51520C1DL);

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

    private void checkMsm(int n, boolean withZerosAndInfinity) {
        AffineG1[] points = new AffineG1[n];
        long[] affine = new long[n * 12];
        BigInteger[] scalars = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            boolean inf = withZerosAndInfinity && i == n / 2;
            AffineG1 a = inf ? AffineG1.INFINITY
                    : JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(i + 3L)).toAffine();
            points[i] = a;
            System.arraycopy(a.x().toLimbs(), 0, affine, i * 12, 6);
            System.arraycopy(a.y().toLimbs(), 0, affine, i * 12 + 6, 6);
            scalars[i] = (withZerosAndInfinity && i % 7 == 0) ? BigInteger.ZERO : new BigInteger(255, RND).mod(R);
        }

        JacobianG1BLS381 oracle = PippengerBLS381.msm(points, scalars);
        long[] out = new long[18];
        PippengerFlatBLS381.msm(out, 0, affine, n, scalars);

        assertArrayEquals(oracleAffine(oracle), flatAffine(out, 0), "flat MSM != oracle at n=" + n);
    }

    @Test
    void matchesOracle_variousSizes() {
        for (int n : new int[]{1, 2, 4, 5, 33, 128, 300}) checkMsm(n, false);
    }

    @Test
    void matchesOracle_withZerosAndInfinity() {
        for (int n : new int[]{5, 33, 128}) checkMsm(n, true);
    }

    @Test
    void scalarsAtOrAboveOrder_reduced() {
        int n = 10;
        AffineG1[] points = new AffineG1[n];
        long[] affine = new long[n * 12];
        BigInteger[] scalars = new BigInteger[n];
        for (int i = 0; i < n; i++) {
            AffineG1 a = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(i + 2L)).toAffine();
            points[i] = a;
            System.arraycopy(a.x().toLimbs(), 0, affine, i * 12, 6);
            System.arraycopy(a.y().toLimbs(), 0, affine, i * 12 + 6, 6);
            scalars[i] = R.add(BigInteger.valueOf(i)); // >= group order, must be reduced identically
        }
        long[] out = new long[18];
        PippengerFlatBLS381.msm(out, 0, affine, n, scalars);
        assertArrayEquals(oracleAffine(PippengerBLS381.msm(points, scalars)), flatAffine(out, 0));
    }
}
