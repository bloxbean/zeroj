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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * ADR-0027 M7 — pure-Java Groth16 prover-scale benchmark for BLS12-381.
 *
 * <p><b>Purpose (the go/no-go for the native-symbolic gadget path):</b> measure how
 * ZeroJ's pure-Java Groth16 {@code setup} and {@code prove} scale toward the ~2M–7M
 * constraint circuits the CIP-1852 derivation needs, so we know — before building the hard
 * Ed25519 / non-native-field gadgets — whether proving is tractable, and whether the
 * {@code zeroj-blst} native path is required.</p>
 *
 * <p><b>Opt-in only.</b> This is heavy (minutes, multi-GB) and never runs in a normal build.
 * Run it via the dedicated Gradle task, which sets the large heap and the {@code zeroj.bench}
 * gate:</p>
 * <pre>{@code
 *   ./gradlew :zeroj-crypto:benchmark
 *   # push the ladder higher (needs more heap):
 *   ./gradlew :zeroj-crypto:benchmark -Dzeroj.bench.logs=12,14,16,18,20
 * }</pre>
 *
 * <p>The synthetic circuit is a modular-squaring chain ({@code a_{i+1} = a_i^2}), which yields
 * exactly {@code N} R1CS constraints with a trivially-computable witness — so the timings
 * reflect the prover/setup machinery (MSMs, FFTs, key-point generation), not gadget logic.</p>
 *
 * <p><b>Finding baked into the harness:</b> the Groth16 prover ({@link Groth16ProverBLS381})
 * uses pure-Java {@code PippengerBLS381} / {@code JacobianG1BLS381} directly — there is no
 * blst-accelerated MSM path wired in today. So this measures the pure-Java baseline; any
 * blst speedup is future work (wiring a native MSM into the prover), and the extrapolation
 * below indicates how much that work matters.</p>
 */
@EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
class Groth16ScaleBenchmark {

    private static final BigInteger FR = MontFr381.modulus();

    @BeforeAll
    static void enableDevSetup() {
        System.setProperty(TrustedSetupPolicy.ALLOW_INSECURE_TRUSTED_SETUP_PROPERTY, "true");
    }

    @Test
    void proverScaleLadder() {
        int[] logs = parseLogs(System.getProperty("zeroj.bench.logs", "12,14,16,18"));

        // tau is all Groth16 setup needs (it derives the structured key from it). Source it
        // cheaply from a tiny SRS instead of building a huge unused powers-of-tau vector.
        BigInteger tau = PowersOfTauBLS381.generate(4).tauScalar();

        System.out.println();
        System.out.println("=== ADR-0027 M7: pure-Java Groth16 scale benchmark (BLS12-381) ===");
        System.out.printf("%-8s %12s %12s %12s %12s %12s%n",
                "log2(N)", "constraints", "setup(s)", "prove(s)", "peakHeap(MB)", "status");

        List<double[]> samples = new ArrayList<>(); // {logN, constraints, setupS, proveS, heapMB}
        for (int logN : logs) {
            int n = 1 << logN;
            try {
                Result r = benchmarkOne(n, tau);
                samples.add(new double[]{logN, n, r.setupSeconds, r.proveSeconds, r.peakHeapMB});
                System.out.printf("%-8d %12d %12.2f %12.2f %12.0f %12s%n",
                        logN, n, r.setupSeconds, r.proveSeconds, r.peakHeapMB, "ok");
            } catch (OutOfMemoryError oom) {
                System.out.printf("%-8d %12d %12s %12s %12s %12s%n",
                        logN, n, "-", "-", "-", "OOM");
                break; // no point trying larger
            }
        }

        if (!samples.isEmpty()) extrapolate(samples);
    }

    // ------------------------------------------------------------------

    private record Result(double setupSeconds, double proveSeconds, double peakHeapMB) {}

    private Result benchmarkOne(int n, BigInteger tau) {
        List<R1CSConstraint> constraints = squaringChain(n);
        int numWires = n + 2;
        BigInteger[] witness = squaringWitness(n);

        var setupBox = new Object() { Groth16ProvingKeyBLS381 pk; };
        double peakSetup = runMeasuringPeakHeapMB(() -> {
            var res = Groth16SetupBLS381.setup(constraints, numWires, 1, tau);
            setupBox.pk = res.provingKey();
        });
        double setupSeconds = LAST_ELAPSED_NANOS.get() / 1e9;

        var proofBox = new Object() { Groth16ProofBLS381 proof; };
        double peakProve = runMeasuringPeakHeapMB(() ->
                proofBox.proof = Groth16ProverBLS381.prove(setupBox.pk, witness, constraints, numWires));
        double proveSeconds = LAST_ELAPSED_NANOS.get() / 1e9;

        if (proofBox.proof == null || !proofBox.proof.a().isOnCurve())
            throw new AssertionError("prove produced invalid proof at N=" + n);

        return new Result(setupSeconds, proveSeconds, Math.max(peakSetup, peakProve));
    }

    /** Modular-squaring chain: exactly {@code n} constraints, wires [0]=1, [1]=out, [2..n+1]=chain. */
    private static List<R1CSConstraint> squaringChain(int n) {
        List<R1CSConstraint> cons = new ArrayList<>(n);
        BigInteger one = BigInteger.ONE;
        for (int i = 0; i < n - 1; i++) {
            cons.add(new R1CSConstraint(Map.of(2 + i, one), Map.of(2 + i, one), Map.of(3 + i, one)));
        }
        // last: a_{n-1} * 1 = output  ->  wire (n+1) * wire 0 = wire 1
        cons.add(new R1CSConstraint(Map.of(n + 1, one), Map.of(0, one), Map.of(1, one)));
        return cons;
    }

    private static BigInteger[] squaringWitness(int n) {
        BigInteger[] w = new BigInteger[n + 2];
        w[0] = BigInteger.ONE;
        BigInteger a = BigInteger.valueOf(5);
        for (int i = 0; i < n; i++) {
            w[2 + i] = a;
            a = a.multiply(a).mod(FR);
        }
        w[1] = w[n + 1]; // output = a_{n-1}
        return w;
    }

    // ------------------------------------------------------------------
    // Peak-heap sampling
    // ------------------------------------------------------------------

    private static final AtomicLong LAST_ELAPSED_NANOS = new AtomicLong();

    /** Run {@code r}, sampling peak used heap; records elapsed nanos in {@link #LAST_ELAPSED_NANOS}. */
    private static double runMeasuringPeakHeapMB(Runnable r) {
        System.gc();
        try { Thread.sleep(50); } catch (InterruptedException ignored) {}
        Runtime rt = Runtime.getRuntime();
        AtomicLong peak = new AtomicLong(rt.totalMemory() - rt.freeMemory());
        AtomicBoolean done = new AtomicBoolean(false);
        Thread sampler = new Thread(() -> {
            while (!done.get()) {
                long used = rt.totalMemory() - rt.freeMemory();
                peak.updateAndGet(p -> Math.max(p, used));
                try { Thread.sleep(20); } catch (InterruptedException e) { return; }
            }
        });
        sampler.setDaemon(true);
        sampler.start();
        long t0 = System.nanoTime();
        r.run();
        LAST_ELAPSED_NANOS.set(System.nanoTime() - t0);
        done.set(true);
        try { sampler.join(200); } catch (InterruptedException ignored) {}
        long used = rt.totalMemory() - rt.freeMemory();
        peak.updateAndGet(p -> Math.max(p, used));
        return peak.get() / (1024.0 * 1024.0);
    }

    // ------------------------------------------------------------------
    // Extrapolation to the target sizes
    // ------------------------------------------------------------------

    private void extrapolate(List<double[]> samples) {
        double[] largest = samples.get(samples.size() - 1);
        double n = largest[1], setupS = largest[2], proveS = largest[3], heapMB = largest[4];
        System.out.println();
        System.out.println("--- Per-constraint cost at the largest measured size (2^"
                + (int) largest[0] + ", " + (long) n + " constraints) ---");
        System.out.printf("  setup: %.2f us/constraint | prove: %.2f us/constraint | heap: %.3f KB/constraint%n",
                setupS * 1e6 / n, proveS * 1e6 / n, heapMB * 1024 / n);
        System.out.println();
        System.out.println("--- Linear extrapolation to ADR-0027 target sizes (lower bound; "
                + "FFT is superlinear, so real prove time is somewhat worse) ---");
        System.out.printf("%-10s %14s %14s %16s%n", "target", "setup(s)", "prove(s)", "peakHeap(GB)");
        for (int logN : new int[]{21, 22, 23}) {
            double tn = 1L << logN;
            double f = tn / n;
            System.out.printf("2^%-8d %14.1f %14.1f %16.1f%n",
                    logN, setupS * f, proveS * f, heapMB * f / 1024.0);
        }
        System.out.println();
        System.out.println("NOTE: prover uses pure-Java Pippenger MSM (no blst path wired in). "
                + "A native-MSM prover would move these numbers; that wiring is future work.");
    }

    private static int[] parseLogs(String csv) {
        String[] parts = csv.split(",");
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; i++) out[i] = Integer.parseInt(parts[i].trim());
        return out;
    }
}
