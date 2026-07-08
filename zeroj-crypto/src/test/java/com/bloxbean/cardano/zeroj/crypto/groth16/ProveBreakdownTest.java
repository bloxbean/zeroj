package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;
import com.bloxbean.cardano.zeroj.api.TrustedSetupPolicy;
import com.bloxbean.cardano.zeroj.bls12381.field.MontFr381;
import com.bloxbean.cardano.zeroj.crypto.setup.Groth16SetupBLS381;
import com.bloxbean.cardano.zeroj.crypto.setup.PowersOfTauBLS381;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * ADR-0029 M8 measure-first: where does pure-Java prove time go — FFT ({@code computeH}) vs the G1/G2
 * MSMs? Decides whether blst-ing G2 + pre-converting the PK (M8) is worth it, or the FFT is the real
 * remaining bottleneck (an M3/FFT concern, not blst).
 */
class ProveBreakdownTest {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void allow() { System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true"); }

    private static List<R1CSConstraint> chain(int n) {
        List<R1CSConstraint> c = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++) c.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        c.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return c;
    }

    private static BigInteger[] wit(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE; BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) { w[2 + i] = a; a = a.multiply(a).mod(FR); }
        w[1] = w[n + 1]; return w;
    }

    @Test
    @EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
    void breakdown() {
        System.out.println("\n=== ADR-0029 M8: pure-Java prove breakdown ===");
        System.out.printf("%-8s %12s %12s %12s%n", "n", "prove(ms)", "computeH(ms)", "FFT %");
        for (int logN : new int[]{12, 14, 16}) {
            int n = 1 << logN;
            var cons = chain(n);
            var w = wit(n);
            int domain = Integer.highestOneBit(Math.max(2, n - 1)) << 1;
            BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();
            var pk = Groth16SetupBLS381.setup(cons, n + 2, 1, tau).provingKey();

            // warm
            Groth16ProverBLS381.prove(pk, w, cons, n + 2, domain);
            Groth16ProverBLS381.computeH(cons, w, cons.size(), domain);

            long t0 = System.nanoTime();
            for (int it = 0; it < 3; it++) Groth16ProverBLS381.prove(pk, w, cons, n + 2, domain);
            double proveMs = (System.nanoTime() - t0) / 3e6;
            long t1 = System.nanoTime();
            for (int it = 0; it < 3; it++) Groth16ProverBLS381.computeH(cons, w, cons.size(), domain);
            double hMs = (System.nanoTime() - t1) / 3e6;

            System.out.printf("2^%-6d %12.1f %12.1f %11.1f%%%n", logN, proveMs, hMs, 100.0 * hMs / proveMs);
        }
        System.out.println("(FFT % high => M3/FFT is the lever; low => M8 blst-G2/pre-conv worth it)");
    }
}
