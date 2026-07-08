package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import supranational.blst.P1;
import supranational.blst.P1_Affine;

import java.math.BigInteger;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M6 spike: measure whether a blst-backed G1 MSM (Pippenger over blst-java's per-op native
 * {@code P1.add}, since 0.3.2 exposes <b>no</b> batched pippenger) beats the optimized pure-Java flat
 * MSM ({@link PippengerFlatBLS381}). The go/no-go for wiring blst into the prover: if per-call JNI
 * overhead erodes the native speedup, Rung A isn't worth it and we'd need Rung B (native pippenger).
 *
 * <p>Correctness runs by default; the timing table is gated behind {@code -Dzeroj.bench=true}.</p>
 */
class BlstMsmSpikeTest {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0xB157A1L);

    // ---- point conversion: AffineG1 -> blst 96-byte uncompressed -> P1_Affine ----

    private static void to48BE(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int srcStart = Math.max(0, be.length - 48);
        int len = be.length - srcStart;
        System.arraycopy(be, srcStart, out, off + 48 - len, len);
    }

    private static P1_Affine toBlst(AffineG1 p) {
        byte[] b = new byte[96];
        if (p.isInfinity()) { b[0] = 0x40; return new P1_Affine(b); }
        to48BE(p.x().toBigInteger(), b, 0);
        to48BE(p.y().toBigInteger(), b, 48);
        return new P1_Affine(b);
    }

    private static BigInteger[] blstAffineXY(P1 result) {
        byte[] s = result.to_affine().serialize(); // 96 bytes uncompressed x||y
        return new BigInteger[]{ new BigInteger(1, java.util.Arrays.copyOfRange(s, 0, 48)),
                new BigInteger(1, java.util.Arrays.copyOfRange(s, 48, 96)) };
    }

    // ---- blst Pippenger MSM (native P1.add) ----

    private static int digit(BigInteger s, int off, int c) {
        int d = 0;
        for (int b = 0; b < c; b++) if (s.testBit(off + b)) d |= (1 << b);
        return d;
    }

    private static P1 blstMsm(P1_Affine[] pts, BigInteger[] scalars, int n) {
        int c = PippengerFlatBLS381.windowSize(n);
        int numBuckets = (1 << c) - 1;
        int numWindows = (255 + c - 1) / c;
        BigInteger twoC = BigInteger.ONE.shiftLeft(c);

        P1 result = null;
        for (int w = numWindows - 1; w >= 0; w--) {
            if (result != null) result = result.mult(twoC); // c doublings in one native call
            P1[] buckets = new P1[numBuckets + 1];
            int off = w * c;
            for (int i = 0; i < n; i++) {
                int d = digit(scalars[i], off, c);
                if (d == 0) continue;
                if (buckets[d] == null) buckets[d] = new P1(pts[i]); else buckets[d].add(pts[i]);
            }
            P1 running = null, windowSum = null;
            for (int j = numBuckets; j >= 1; j--) {
                if (buckets[j] != null) {
                    if (running == null) running = new P1(buckets[j].serialize()); else running.add(buckets[j]);
                }
                if (running != null) {
                    if (windowSum == null) windowSum = new P1(running.serialize()); else windowSum.add(running);
                }
            }
            if (windowSum != null) result = (result == null) ? windowSum : result.add(windowSum);
        }
        return result;
    }

    // ---- build inputs ----

    private static AffineG1[] points(int n) {
        AffineG1[] pts = new AffineG1[n];
        for (int i = 0; i < n; i++) pts[i] = JacobianG1BLS381.GENERATOR.scalarMul(BigInteger.valueOf(i + 2L)).toAffine();
        return pts;
    }

    private static BigInteger[] scalars(int n) {
        BigInteger[] s = new BigInteger[n];
        for (int i = 0; i < n; i++) s[i] = new BigInteger(255, RND).mod(R);
        return s;
    }

    private static long[] flat(AffineG1[] pts) {
        long[] f = new long[pts.length * 12];
        for (int i = 0; i < pts.length; i++) {
            System.arraycopy(pts[i].x().toLimbs(), 0, f, i * 12, 6);
            System.arraycopy(pts[i].y().toLimbs(), 0, f, i * 12 + 6, 6);
        }
        return f;
    }

    @Test
    void blstMsm_matchesPureJava() {
        for (int n : new int[]{1, 5, 64, 300}) {
            AffineG1[] pts = points(n);
            BigInteger[] sc = scalars(n);

            var pure = PippengerFlatBLS381.msmFlat(flat(pts), n, sc).toAffine();
            P1_Affine[] blstPts = new P1_Affine[n];
            for (int i = 0; i < n; i++) blstPts[i] = toBlst(pts[i]);
            BigInteger[] blst = blstAffineXY(blstMsm(blstPts, sc, n));

            assertEquals(pure.x().toBigInteger(), blst[0], "x mismatch n=" + n);
            assertEquals(pure.y().toBigInteger(), blst[1], "y mismatch n=" + n);
        }
    }

    @Test
    @EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
    void timing_blstVsPureJava() {
        System.out.println("\n=== ADR-0029 M6 spike: blst MSM vs pure-Java flat MSM ===");
        System.out.printf("%-8s %14s %14s %10s%n", "n", "pureJava(ms)", "blst(ms)", "speedup");
        for (int logN : new int[]{12, 14, 16}) {
            int n = 1 << logN;
            AffineG1[] pts = points(n);
            BigInteger[] sc = scalars(n);
            long[] f = flat(pts);
            P1_Affine[] blstPts = new P1_Affine[n];
            for (int i = 0; i < n; i++) blstPts[i] = toBlst(pts[i]);

            // warm + time (3 iters each)
            for (int it = 0; it < 1; it++) { PippengerFlatBLS381.msmFlat(f, n, sc); blstMsm(blstPts, sc, n); }
            long t0 = System.nanoTime();
            for (int it = 0; it < 3; it++) PippengerFlatBLS381.msmFlat(f, n, sc);
            double pureMs = (System.nanoTime() - t0) / 3e6;
            long t1 = System.nanoTime();
            for (int it = 0; it < 3; it++) blstMsm(blstPts, sc, n);
            double blstMs = (System.nanoTime() - t1) / 3e6;

            System.out.printf("2^%-6d %14.1f %14.1f %9.2fx%n", logN, pureMs, blstMs, pureMs / blstMs);
        }
        System.out.println("(speedup > 1 => blst faster; conversion cost excluded — measured on prebuilt P1_Affine)");
    }
}
