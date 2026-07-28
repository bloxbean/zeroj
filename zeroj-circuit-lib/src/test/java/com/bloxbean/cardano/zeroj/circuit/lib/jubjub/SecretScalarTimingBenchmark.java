package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.function.Supplier;

/**
 * ADR-0038 P4 benchmark matrix. <b>Not a gate.</b>
 *
 * <p>Disabled in the ordinary {@code test} task. Nothing here asserts: a timing assertion in CI
 * is flaky, and — more importantly — a timing harness that fails to find a leak does not
 * establish that there is none. The deterministic add/double operation-count gate in
 * {@link SecretScalarScheduleTest} is what CI enforces; this records what the trade actually
 * cost and what variance survives it.
 *
 * <p>ADR-0038 requires these six cases measured separately, because a single figure quoted for
 * "sign" or "commit" is what produced the wrong estimates in the first place: the two signing
 * APIs differ by a whole scalar multiplication, and a small-value commitment is affected far
 * more than a full-width one.
 *
 * <p>Run:
 * <pre>./gradlew :zeroj-circuit-lib:secretScalarBenchmark</pre>
 */
@EnabledIfSystemProperty(named = "zeroj.bench", matches = "true")
class SecretScalarTimingBenchmark {

    private static final int WARMUP = 200;
    private static final int SAMPLES = 400;

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    @Test
    void benchmarkMatrix() {
        BigInteger sk = new BigInteger(
                "271828182845904523536028747135266249775724709369995957496696762772407663", 10).mod(L);
        var keypair = EdDSAJubjub.keypairFromSecret(sk);
        BigInteger msg = EdDSAJubjub.hashToField("adr-0038 benchmark".getBytes());

        BigInteger smallValue = BigInteger.valueOf(1_000_000L);
        BigInteger fullBlinding = new BigInteger(
                "31415926535897932384626433832795028841971693993751058209749445923078164").mod(L);
        BigInteger fullValue = new BigInteger(
                "16180339887498948482045868343656381177203091798057628621354486227052604").mod(L);
        var signature = EdDSAJubjub.sign(keypair, msg);
        var commitment = PedersenCommitment.commit(fullValue, fullBlinding);

        System.out.println("\n=== ADR-0038 P4 benchmark matrix ===");
        System.out.printf("JVM       : %s %s%n", System.getProperty("java.vm.name"),
                System.getProperty("java.version"));
        System.out.printf("OS/arch   : %s %s (%s)%n", System.getProperty("os.name"),
                System.getProperty("os.version"),
                System.getProperty("os.arch"));
        System.out.printf("cores     : %d%n", Runtime.getRuntime().availableProcessors());
        System.out.printf("max heap  : %.1f GiB%n",
                Runtime.getRuntime().maxMemory() / (1024.0 * 1024.0 * 1024.0));
        System.out.printf("warmup    : %d, samples: %d%n%n", WARMUP, SAMPLES);
        System.out.printf("%-46s %10s %25s %10s %10s%n",
                "case", "median", "exact 95% median CI", "p10", "p90");

        // The six cases ADR-0038 names, plus the primitive they all rest on.
        report("raw fixed-252 primitive [not production]",
                () -> G.scalarMulSecretRaw252UnsafeForTiming(fullValue));
        report("scalarMulSecretBlinded (actual secret path)",
                () -> G.scalarMulSecretBlindedBestEffort(fullValue));
        report("scalarMul (variable, full-width) [public path]",
                () -> G.scalarMul(fullValue));
        report("scalarMul (variable, 64-bit) [public path]",
                () -> G.scalarMul(smallValue));

        report("sign(Keypair, msg)          [primary]",
                () -> EdDSAJubjub.sign(keypair, msg));
        report("sign(BigInteger, msg)       [deprecated]",
                () -> deprecatedSign(sk, msg));
        report("keypairFromSecret",
                () -> EdDSAJubjub.keypairFromSecret(sk));

        report("commit(small value, full blinding)",
                () -> PedersenCommitment.commit(smallValue, fullBlinding));
        report("commit(full value, full blinding)",
                () -> PedersenCommitment.commit(fullValue, fullBlinding));
        report("commit(0, full blinding)    [boundary]",
                () -> PedersenCommitment.commit(BigInteger.ZERO, fullBlinding));
        report("commit(l-1, full blinding)  [boundary]",
                () -> PedersenCommitment.commit(L.subtract(BigInteger.ONE), fullBlinding));

        // Precompute signature/commitment above: putting sign/commit inside these lambdas would
        // time two operations and repeat the ADR-0038 P4 measurement error.
        report("EdDSA verify (precomputed signature)",
                () -> EdDSAJubjub.verify(keypair.pk(), msg, signature));
        report("Pedersen verify (public opening path)",
                () -> PedersenCommitment.verify(
                        commitment, fullValue, fullBlinding));

        System.out.println("""

                Residual variance this decision does NOT remove, and which the numbers above
                still contain: BigInteger word-count variance inside the fixed schedules and in
                S = r + k*sk mod l; the mod reductions and fresh scalar blinding in commit();
                secret-dependent Java selection branches; and Poseidon nonce derivation, which
                processes sk through variable-time BigInteger arithmetic. The add/double schedule
                is fixed and the raw trailing-zero count is blinded at production call sites; the
                arithmetic underneath is not constant-time. Signing and off-circuit commitment
                generation remain offline-only.
                """);
    }

    @SuppressWarnings("deprecation")
    private static Object deprecatedSign(BigInteger sk, BigInteger msg) {
        return EdDSAJubjub.sign(sk, msg);
    }

    private static void report(String label, Supplier<Object> op) {
        for (int i = 0; i < WARMUP; i++) op.get();

        long[] ns = new long[SAMPLES];
        for (int i = 0; i < SAMPLES; i++) {
            long t0 = System.nanoTime();
            Object r = op.get();
            ns[i] = System.nanoTime() - t0;
            if (r == null) throw new IllegalStateException("operation returned null");
        }
        Arrays.sort(ns);
        int lowerMedianIndex = exactMedianLowerIndex(ns.length);
        int upperMedianIndex = ns.length - lowerMedianIndex - 1;
        System.out.printf("%-46s %9.3fms [%9.3fms, %9.3fms] %9.3fms %9.3fms%n", label,
                ns[SAMPLES / 2] / 1e6,
                ns[lowerMedianIndex] / 1e6,
                ns[upperMedianIndex] / 1e6,
                ns[SAMPLES / 10] / 1e6,
                ns[SAMPLES * 9 / 10] / 1e6);
    }

    /**
     * Lower zero-based order-statistic index for a distribution-free 95% confidence interval
     * on the population median. The upper index is {@code n - lower - 1}. This uses the exact
     * Binomial(n, 1/2) tails rather than a normal approximation.
     */
    private static int exactMedianLowerIndex(int n) {
        BigInteger denominator = BigInteger.ONE.shiftLeft(n);
        BigInteger cumulative = BigInteger.ZERO;
        BigInteger choose = BigInteger.ONE; // C(n, 0)
        int accepted = 0;
        for (int i = 0; i < n / 2; i++) {
            cumulative = cumulative.add(choose);
            // two-sided alpha=.05 => each tail <= .025 = 1/40
            if (cumulative.multiply(BigInteger.valueOf(40)).compareTo(denominator) <= 0) {
                accepted = i;
            } else {
                break;
            }
            choose = choose.multiply(BigInteger.valueOf(n - i))
                    .divide(BigInteger.valueOf(i + 1L));
        }
        return accepted;
    }

    /**
     * Correlation probe for the raw fixed-252 primitive and the actual blinded secret path.
     * The raw column is expected to track {@code lowestSetBit}: while the accumulator remains
     * the identity its small coordinates are cheaper. Blinding should break that relation, but
     * a flatter profile is <b>not</b> proof of constant time — this is one machine, one JVM and
     * one run over a variable-time BigInteger layer.
     */
    @Test
    void bitLengthAndWeightCorrelation() {
        System.out.println("\n=== raw vs blinded secret-scalar timing correlation ===");
        System.out.printf("%-14s %8s %8s %8s %11s %11s%n",
                "scalar", "bits", "weight", "ctz", "raw median", "blinded");

        var rng = new SecureRandom(new byte[]{7});
        record Probe(String name, BigInteger k) {}
        var probes = new Probe[]{
                new Probe("zero", BigInteger.ZERO),
                new Probe("one", BigInteger.ONE),
                new Probe("2^64", BigInteger.ONE.shiftLeft(64)),
                new Probe("2^128", BigInteger.ONE.shiftLeft(128)),
                new Probe("2^251", BigInteger.ONE.shiftLeft(251)),
                new Probe("low-weight", BigInteger.ONE.shiftLeft(251).or(BigInteger.ONE)),
                new Probe("dense", BigInteger.ONE.shiftLeft(251).subtract(BigInteger.ONE)),
                new Probe("l-1", L.subtract(BigInteger.ONE)),
                new Probe("random", new BigInteger(L.bitLength(), rng).mod(L)),
        };

        for (var probe : probes) {
            for (int i = 0; i < WARMUP; i++) {
                G.scalarMulSecretRaw252UnsafeForTiming(probe.k());
                G.scalarMulSecretBlindedBestEffort(probe.k());
            }
            long[] rawNs = new long[SAMPLES];
            long[] blindedNs = new long[SAMPLES];
            for (int i = 0; i < SAMPLES; i++) {
                long t0 = System.nanoTime();
                G.scalarMulSecretRaw252UnsafeForTiming(probe.k());
                rawNs[i] = System.nanoTime() - t0;
                t0 = System.nanoTime();
                G.scalarMulSecretBlindedBestEffort(probe.k());
                blindedNs[i] = System.nanoTime() - t0;
            }
            Arrays.sort(rawNs);
            Arrays.sort(blindedNs);
            int ctz = probe.k().signum() == 0 ? -1 : probe.k().getLowestSetBit();
            System.out.printf("%-14s %8d %8d %8d %10.3fms %10.3fms%n", probe.name(),
                    probe.k().bitLength(), probe.k().bitCount(), ctz,
                    rawNs[SAMPLES / 2] / 1e6, blindedNs[SAMPLES / 2] / 1e6);
        }
        System.out.println("\nA flatter blinded column is evidence about this run only. It is "
                + "not proof of constant time.\n");
    }
}
