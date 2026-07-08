package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import com.bloxbean.cardano.zeroj.blst.ffm.BlstG1Msm;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M6 / Rung B: the FFM batched blst MSM ({@code blst_p1s_mult_pippenger}, one native call)
 * must equal the pure-Java flat MSM, and — the point of the whole exercise — should be materially
 * faster (unlike the per-op wrapper spike, which was a wash).
 */
class BlstFfmMsmTest {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0xFF33A1L);

    private static void to48BE(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int srcStart = Math.max(0, be.length - 48);
        int len = be.length - srcStart;
        System.arraycopy(be, srcStart, out, off + 48 - len, len);
    }

    private static byte[] uncompressed(AffineG1 p) {
        byte[] b = new byte[96];
        if (p.isInfinity()) { b[0] = 0x40; return b; }
        to48BE(p.x().toBigInteger(), b, 0);
        to48BE(p.y().toBigInteger(), b, 48);
        return b;
    }

    private static BigInteger[] resultXY(byte[] uncompressed96) {
        if ((uncompressed96[0] & 0x40) != 0) return null; // infinity
        return new BigInteger[]{ new BigInteger(1, Arrays.copyOfRange(uncompressed96, 0, 48)),
                new BigInteger(1, Arrays.copyOfRange(uncompressed96, 48, 96)) };
    }

    private static AffineG1[] points(int n) {
        AffineG1[] p = new AffineG1[n];
        for (int i = 0; i < n; i++) p[i] = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(i + 2L)).toAffine();
        return p;
    }

    private static BigInteger[] scalars(int n) {
        BigInteger[] s = new BigInteger[n];
        for (int i = 0; i < n; i++) s[i] = new BigInteger(255, RND).mod(R);
        return s;
    }

    private static long[] flat(AffineG1[] p) {
        long[] f = new long[p.length * 12];
        for (int i = 0; i < p.length; i++) {
            System.arraycopy(p[i].x().toLimbs(), 0, f, i * 12, 6);
            System.arraycopy(p[i].y().toLimbs(), 0, f, i * 12 + 6, 6);
        }
        return f;
    }

    @Test
    void diag_singlePointKnownScalar() {
        // 3 · G : isolates scalar handling from the batched path.
        AffineG1 g = JacobianG1BLS381.GENERATOR.toAffine();
        BigInteger k = BigInteger.valueOf(3);
        byte[] res = BlstG1Msm.msm(new byte[][]{uncompressed(g)}, new BigInteger[]{k});
        BigInteger[] xy = resultXY(res);
        var expected = JacobianG1BLS381.GENERATOR.scalarMul(k).toAffine();
        assertNotNull(xy);
        assertEquals(expected.x().toBigInteger(), xy[0], "3·G x (n=1 single-mul fallback)");
    }

    @Test
    void ffmBatchedMsm_matchesPureJava() {
        for (int n : new int[]{1, 5, 64, 300, 1000}) {
            AffineG1[] pts = points(n);
            BigInteger[] sc = scalars(n);

            var pure = PippengerFlatBLS381.msmFlat(flat(pts), n, sc).toAffine();
            byte[][] enc = new byte[n][];
            for (int i = 0; i < n; i++) enc[i] = uncompressed(pts[i]);
            BigInteger[] blst = resultXY(BlstG1Msm.msm(enc, sc));

            assertNotNull(blst, "blst result unexpectedly infinity at n=" + n);
            assertEquals(pure.x().toBigInteger(), blst[0], "x mismatch n=" + n);
            assertEquals(pure.y().toBigInteger(), blst[1], "y mismatch n=" + n);
        }
    }

    @Test
    @EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
    void timing_ffmBatchedVsPureJava() {
        System.out.println("\n=== ADR-0029 M6 Rung B: FFM batched blst MSM vs pure-Java flat MSM ===");
        System.out.printf("%-8s %14s %14s %10s%n", "n", "pureJava(ms)", "blstFFM(ms)", "speedup");
        for (int logN : new int[]{12, 14, 16, 18}) {
            int n = 1 << logN;
            AffineG1[] pts = points(n);
            BigInteger[] sc = scalars(n);
            long[] f = flat(pts);
            byte[][] enc = new byte[n][];
            for (int i = 0; i < n; i++) enc[i] = uncompressed(pts[i]);

            for (int it = 0; it < 1; it++) { PippengerFlatBLS381.msmFlat(f, n, sc); BlstG1Msm.msm(enc, sc); }
            long t0 = System.nanoTime();
            for (int it = 0; it < 3; it++) PippengerFlatBLS381.msmFlat(f, n, sc);
            double pureMs = (System.nanoTime() - t0) / 3e6;
            long t1 = System.nanoTime();
            for (int it = 0; it < 3; it++) BlstG1Msm.msm(enc, sc);
            double blstMs = (System.nanoTime() - t1) / 3e6;
            System.out.printf("2^%-6d %14.1f %14.1f %9.2fx%n", logN, pureMs, blstMs, pureMs / blstMs);
        }
    }
}
