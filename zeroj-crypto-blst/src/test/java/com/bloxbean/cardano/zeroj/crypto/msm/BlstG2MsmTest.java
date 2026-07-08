package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import com.bloxbean.cardano.zeroj.blst.ffm.BlstG2Msm;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M8: the FFM batched blst G2 MSM ({@code blst_p2s_mult_pippenger}) must equal a naive
 * pure-Java G2 MSM. Also validates the Fp2 byte order (c1‖c0, imaginary-first) via a single 3·G check.
 */
class BlstG2MsmTest {

    private static final BigInteger R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);
    private static final Random RND = new Random(0x62A1B2L);

    private static void to48BE(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48);
        System.arraycopy(be, s, out, off + 48 - (be.length - s), be.length - s);
    }

    private static byte[] uncompressed(AffineG2 p) {
        byte[] b = new byte[192];
        if (p.equals(AffineG2.INFINITY) || (p.x().re().isZero() && p.x().im().isZero()
                && p.y().re().isZero() && p.y().im().isZero())) { b[0] = 0x40; return b; }
        to48BE(p.x().im().toBigInteger(), b, 0);    // x.c1
        to48BE(p.x().re().toBigInteger(), b, 48);   // x.c0
        to48BE(p.y().im().toBigInteger(), b, 96);   // y.c1
        to48BE(p.y().re().toBigInteger(), b, 144);  // y.c0
        return b;
    }

    /** [x.c1, x.c0, y.c1, y.c0] as BigInteger, or null for infinity. */
    private static BigInteger[] result(byte[] u) {
        if ((u[0] & 0x40) != 0) return null;
        return new BigInteger[]{
                new BigInteger(1, Arrays.copyOfRange(u, 0, 48)),
                new BigInteger(1, Arrays.copyOfRange(u, 48, 96)),
                new BigInteger(1, Arrays.copyOfRange(u, 96, 144)),
                new BigInteger(1, Arrays.copyOfRange(u, 144, 192)) };
    }

    private static BigInteger[] oracleAffine(JacobianG2BLS381 j) {
        if (j.isInfinity()) return null;
        var a = j.toAffine();
        return new BigInteger[]{ a.x().im().toBigInteger(), a.x().re().toBigInteger(),
                a.y().im().toBigInteger(), a.y().re().toBigInteger() };
    }

    @Test
    void diag_g2ByteOrder_3G() {
        var g = JacobianG2BLS381.GENERATOR.toAffine();
        byte[] res = BlstG2Msm.msm(new byte[][]{uncompressed(g)}, new BigInteger[]{BigInteger.valueOf(3)});
        assertArrayEquals(oracleAffine(JacobianG2BLS381.GENERATOR.scalarMul(BigInteger.valueOf(3))), result(res),
                "3·G2 (validates c1‖c0 Fp2 byte order)");
    }

    @Test
    void batchG2Msm_matchesNaive() {
        for (int n : new int[]{2, 8, 64, 200}) {
            AffineG2[] pts = new AffineG2[n];
            BigInteger[] sc = new BigInteger[n];
            JacobianG2BLS381 oracle = JacobianG2BLS381.INFINITY;
            byte[][] enc = new byte[n][];
            for (int i = 0; i < n; i++) {
                var pj = JacobianG2BLS381.GENERATOR.scalarMul(BigInteger.valueOf(i + 2L));
                pts[i] = pj.toAffine();
                sc[i] = new BigInteger(255, RND).mod(R);
                enc[i] = uncompressed(pts[i]);
                oracle = oracle.add(pj.scalarMul(sc[i]));
            }
            assertArrayEquals(oracleAffine(oracle), result(BlstG2Msm.msm(enc, sc)), "G2 MSM mismatch n=" + n);
        }
    }
}
