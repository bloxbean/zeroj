package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import com.bloxbean.cardano.zeroj.cryptoblst.BlstProverBackend;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ADR-0029: the {@link BlstProverBackend} wired into {@link Groth16ProverBLS381} must produce the
 * same proof as pure Java (unblinded ⇒ deterministic) and be materially faster (the MSMs dominate).
 */
class BlstProverBenchTest {

    private static final BigInteger FR = MontFr381.modulus();
    private static final ProverBackend BLST = BlstProverBackend.create();

    @BeforeAll
    static void allowDevSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

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
        assertEquals(pure.b().x().re().toBigInteger(), blst.b().x().re().toBigInteger(), "piB.x.c0");
        assertEquals(pure.b().x().im().toBigInteger(), blst.b().x().im().toBigInteger(), "piB.x.c1");
        assertEquals(pure.b().y().re().toBigInteger(), blst.b().y().re().toBigInteger(), "piB.y.c0");
    }

    @Test
    @EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
    void timing_blstBackedProve() {
        System.out.println("\n=== ADR-0029: full prove — pure-Java vs FFM-blst backend (G1+G2) ===");
        System.out.printf("%-8s %14s %14s %10s%n", "n", "pureJava(ms)", "blst(ms)", "speedup");
        for (int logN : new int[]{12, 14, 16}) {
            int n = 1 << logN;
            var s = setup(n);
            var readers = Groth16ProverBLS381.heapReaders(s.pk);
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
