package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFp381;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.blst.ffm.BlstG1Msm;
import com.bloxbean.cardano.zeroj.crypto.msm.G1MsmBackend;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029 M7: an FFM-blst {@link G1MsmBackend} wired into the prover must produce the same proof as
 * pure-Java (unblinded ⇒ deterministic), and should make the whole prove faster (the G1 MSMs
 * dominate). Point conversion (flat Montgomery limbs → blst 96-byte uncompressed) happens per MSM
 * here; production would pre-convert the fixed PK once.
 */
class BlstProverBenchTest {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allowDevSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    // ---- the blst G1 MSM backend (FFM) ----

    private static void to48BE(BigInteger v, byte[] out, int off) {
        byte[] be = v.toByteArray();
        int s = Math.max(0, be.length - 48);
        System.arraycopy(be, s, out, off + 48 - (be.length - s), be.length - s);
    }

    private static byte[] uncompressed(long[] buf12) {
        boolean inf = true;
        for (long l : buf12) if (l != 0) { inf = false; break; }
        byte[] b = new byte[96];
        if (inf) { b[0] = 0x40; return b; }
        MontFp381 x = MontFp381.fromMontLimbs(buf12[0], buf12[1], buf12[2], buf12[3], buf12[4], buf12[5]);
        MontFp381 y = MontFp381.fromMontLimbs(buf12[6], buf12[7], buf12[8], buf12[9], buf12[10], buf12[11]);
        to48BE(x.toBigInteger(), b, 0);
        to48BE(y.toBigInteger(), b, 48);
        return b;
    }

    private static final com.bloxbean.cardano.zeroj.crypto.msm.G1MsmBackend BLST_G1 = (reader, n, scalars) -> {
        byte[][] enc = new byte[n][];
        long[] buf = new long[12];
        for (int i = 0; i < n; i++) { reader.readInto(i, buf); enc[i] = uncompressed(buf); }
        byte[] res = BlstG1Msm.msm(enc, scalars);
        if ((res[0] & 0x40) != 0) return JacobianG1BLS381.INFINITY;
        return JacobianG1BLS381.fromAffine(new BigInteger(1, Arrays.copyOfRange(res, 0, 48)),
                new BigInteger(1, Arrays.copyOfRange(res, 48, 96)));
    };

    private static byte[] uncompressedG2(com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2 p) {
        byte[] b = new byte[192];
        if (p.x().re().isZero() && p.x().im().isZero() && p.y().re().isZero() && p.y().im().isZero()) { b[0] = 0x40; return b; }
        to48BE(p.x().im().toBigInteger(), b, 0);   to48BE(p.x().re().toBigInteger(), b, 48);
        to48BE(p.y().im().toBigInteger(), b, 96);  to48BE(p.y().re().toBigInteger(), b, 144);
        return b;
    }

    private static final com.bloxbean.cardano.zeroj.crypto.msm.G2MsmBackend BLST_G2 = (points, scalars, n) -> {
        if (n == 0) return com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.INFINITY;
        byte[][] enc = new byte[n][];
        BigInteger[] sc = new BigInteger[n];
        for (int i = 0; i < n; i++) { enc[i] = uncompressedG2(points[i]); sc[i] = scalars[i]; }
        byte[] r = com.bloxbean.cardano.zeroj.blst.ffm.BlstG2Msm.msm(enc, sc);
        if ((r[0] & 0x40) != 0) return com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.INFINITY;
        var xc1 = new BigInteger(1, Arrays.copyOfRange(r, 0, 48)); var xc0 = new BigInteger(1, Arrays.copyOfRange(r, 48, 96));
        var yc1 = new BigInteger(1, Arrays.copyOfRange(r, 96, 144)); var yc0 = new BigInteger(1, Arrays.copyOfRange(r, 144, 192));
        return com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.fromAffine(
                com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381.of(xc0, xc1),
                com.bloxbean.cardano.zeroj.bls12381.field.MontFp2_381.of(yc0, yc1));
    };

    private static final ProverBackend BLST = new ProverBackend(BLST_G1, BLST_G2);

    // ---- circuit ----

    private static List<R1CSConstraint> squaringChain(int n) {
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++)
            cons.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return cons;
    }

    private static BigInteger[] witness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1];
        return w;
    }

    private record Setup(Groth16ProvingKeyBLS381 pk, List<R1CSConstraint> cons, BigInteger[] w, int domain) {}

    private static Setup setup(int n) {
        var cons = squaringChain(n);
        var w = witness(n);
        int domain = Integer.highestOneBit(Math.max(2, n - 1)) << 1;
        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
        var pk = Groth16SetupBLS381.setup(cons, n + 2, 1, tau).provingKey();
        return new Setup(pk, cons, w, domain);
    }

    @Test
    void blstBackedProof_equalsPureJava() {
        var s = setup(1024);
        var readers = Groth16ProverBLS381.heapReaders(s.pk);
        var pure = Groth16ProverBLS381.proveUnblindedWithReaders(s.pk, readers, ProverBackend.PURE_JAVA, s.w, s.cons, s.domain);
        var blst = Groth16ProverBLS381.proveUnblindedWithReaders(s.pk, readers, BLST, s.w, s.cons, s.domain);

        assertEquals(pure.a().x().toBigInteger(), blst.a().x().toBigInteger(), "piA.x");
        assertEquals(pure.a().y().toBigInteger(), blst.a().y().toBigInteger(), "piA.y");
        assertEquals(pure.c().x().toBigInteger(), blst.c().x().toBigInteger(), "piC.x");
        assertEquals(pure.c().y().toBigInteger(), blst.c().y().toBigInteger(), "piC.y");
        // piB is G2 (now blst too)
        assertEquals(pure.b().x().re().toBigInteger(), blst.b().x().re().toBigInteger(), "piB.x.c0");
        assertEquals(pure.b().x().im().toBigInteger(), blst.b().x().im().toBigInteger(), "piB.x.c1");
        assertEquals(pure.b().y().re().toBigInteger(), blst.b().y().re().toBigInteger(), "piB.y.c0");
    }

    @Test
    @EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
    void timing_blstBackedProve() {
        System.out.println("\n=== ADR-0029 M7: full prove — pure-Java vs FFM-blst G1 backend ===");
        System.out.printf("%-8s %14s %14s %10s%n", "n", "pureJava(ms)", "blst(ms)", "speedup");
        for (int logN : new int[]{12, 14, 16}) {
            int n = 1 << logN;
            var s = setup(n);
            var readers = Groth16ProverBLS381.heapReaders(s.pk);
            // warm
            Groth16ProverBLS381.proveWithReaders(s.pk, readers, ProverBackend.PURE_JAVA, s.w, s.cons, n + 2, s.domain);
            Groth16ProverBLS381.proveWithReaders(s.pk, readers, BLST, s.w, s.cons, n + 2, s.domain);
            long t0 = System.nanoTime();
            for (int it = 0; it < 3; it++)
                Groth16ProverBLS381.proveWithReaders(s.pk, readers, ProverBackend.PURE_JAVA, s.w, s.cons, n + 2, s.domain);
            double pureMs = (System.nanoTime() - t0) / 3e6;
            long t1 = System.nanoTime();
            for (int it = 0; it < 3; it++)
                Groth16ProverBLS381.proveWithReaders(s.pk, readers, BLST, s.w, s.cons, n + 2, s.domain);
            double blstMs = (System.nanoTime() - t1) / 3e6;
            System.out.printf("2^%-6d %14.1f %14.1f %9.2fx%n", logN, pureMs, blstMs, pureMs / blstMs);
        }
    }
}
