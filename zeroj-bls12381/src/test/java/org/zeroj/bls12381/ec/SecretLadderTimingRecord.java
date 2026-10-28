package org.zeroj.bls12381.ec;

import org.zeroj.bls12381.Bls12381Generators;
import org.zeroj.bls12381.pedersen.G1Pedersen;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/**
 * ADR-0062 D1 evidence (in the style of ADR-0038 P7.4): wall-clock timing of the pure-Java secret
 * ladders ({@link G1Point#ctScalarMul}) across scalar bit lengths and Hamming weights, and of G1
 * Pedersen generation for the values 0, 1 and random. It records numbers and asserts nothing.
 * Before D1 the cost grew linearly with the bit length (about 0.22 ms at 1 bit to 0.93 ms at
 * 255 bits, ADR-0062 F1); the r1–r3 blinded ladder still separated {@code k = 0} (F12). A timing
 * record is evidence, not proof of constant time.
 *
 * <p>Samples are interleaved round-robin across classes so drift affects every class equally. For
 * each class it prints the median and an exact (order-statistic, binomial) 95% confidence interval
 * of the median. Run: {@code ./gradlew :zeroj-bls12381:secretLadderTimingRecord}.</p>
 */
final class SecretLadderTimingRecord {
    private static final BigInteger R = G1Point.R;
    private static final int WARMUP = 1500;
    private static final int SAMPLES = 1001;
    private static volatile Object sink;

    private SecretLadderTimingRecord() {}

    public static void main(String[] args) {
        G1Point base = Bls12381Generators.G1;
        Random random = new Random(0x0062_0D01L);
        Map<String, BigInteger> classes = new LinkedHashMap<>();
        classes.put("bitlen 1 (k = 1)", BigInteger.ONE);
        classes.put("bitlen 65", BigInteger.ONE.shiftLeft(64).or(new BigInteger(64, random)));
        classes.put("bitlen 129", BigInteger.ONE.shiftLeft(128).or(new BigInteger(128, random)));
        classes.put("bitlen 192", BigInteger.ONE.shiftLeft(191).or(new BigInteger(191, random)));
        classes.put("bitlen 255, random", new BigInteger(255, random).setBit(254).mod(R));
        classes.put("bitlen 255, HW low", BigInteger.ONE.shiftLeft(254).add(BigInteger.ONE));
        classes.put("bitlen 255, HW high", R.subtract(BigInteger.ONE));
        classes.put("k = 0", BigInteger.ZERO);

        List<BigInteger> scalars = new ArrayList<>(classes.values());
        JacobianG1BLS381 jac = JacobianG1BLS381.GENERATOR;
        System.out.printf("ADR-0062 D1 secret-ladder timing record (G1, pure Java), %d samples per class%n", SAMPLES);
        System.out.printf("java %s, %s %s, %d cores%n", System.getProperty("java.version"),
                System.getProperty("os.name"), System.getProperty("os.arch"), Runtime.getRuntime().availableProcessors());
        record("ladders only (JacobianG1BLS381, split, base pre-validated)", classes, scalars,
                k -> jac.ctScalarMulInSubgroup(k, SecretLadder.SECURE));
        record("G1Point.ctScalarMul (subgroup check + split ladders, as the provider calls it)", classes, scalars,
                base::ctScalarMul);

        // ADR-0062 r4 requirement 5: G1 Pedersen commit(0) vs commit(1) vs commit(random), with a
        // fresh uniform blinding per sample shared by the three classes.
        G1Pedersen pedersen = G1Pedersen.pureJava();
        Map<String, BigInteger> values = new LinkedHashMap<>();
        values.put("commit(0)", BigInteger.ZERO);
        values.put("commit(1)", BigInteger.ONE);
        values.put("commit(random)", new BigInteger(255, random).mod(R));
        List<BigInteger> valueList = new ArrayList<>(values.values());
        SecureRandom blindings = new SecureRandom();
        BigInteger[] blinding = {G1Pedersen.randomBlinding(blindings)};
        record("G1Pedersen.commitScalar (pure Java)", values, valueList, v -> {
            if (v == valueList.get(0)) blinding[0] = G1Pedersen.randomBlinding(blindings);
            return pedersen.commitScalar(v, blinding[0]);
        });
    }

    private static void record(String title, Map<String, BigInteger> classes, List<BigInteger> scalars,
                               Function<BigInteger, Object> op) {
        for (int i = 0; i < WARMUP; i++) {
            sink = op.apply(scalars.get(i % scalars.size()));
        }
        long[][] ns = new long[scalars.size()][SAMPLES];
        for (int s = 0; s < SAMPLES; s++) {
            for (int c = 0; c < scalars.size(); c++) {
                long t0 = System.nanoTime();
                sink = op.apply(scalars.get(c));
                ns[c][s] = System.nanoTime() - t0;
            }
        }
        int[] ci = medianConfidenceRanks(SAMPLES);
        System.out.printf("%n%s%n%-22s %10s %22s%n", title, "class", "median ms", "95% CI of median (ms)");
        int c = 0;
        for (String name : classes.keySet()) {
            long[] sorted = ns[c++].clone();
            Arrays.sort(sorted);
            System.out.printf("%-22s %10.3f   [%7.3f, %7.3f]%n", name, sorted[SAMPLES / 2] / 1e6,
                    sorted[ci[0]] / 1e6, sorted[ci[1]] / 1e6);
        }
    }

    /**
     * Ranks {@code (lo, hi)} (0-based) of the order statistics that bound the median with at least
     * 95% coverage: {@code P(lo < X <= hi) >= 0.95} for {@code X ~ Binomial(n, 1/2)}.
     */
    static int[] medianConfidenceRanks(int n) {
        double[] cdf = new double[n + 1];
        double logPmf = -n * Math.log(2);
        double acc = 0;
        for (int i = 0; i <= n; i++) {
            acc += Math.exp(logPmf);
            cdf[i] = acc;
            if (i < n) logPmf += Math.log((double) (n - i) / (i + 1));
        }
        int lo = 0;
        while (lo + 1 < n && cdf[lo + 1] <= 0.025) lo++;
        int hi = n - 1;
        while (hi - 1 > lo && 1 - cdf[hi - 1] <= 0.025) hi--;
        return new int[]{lo, hi};
    }
}
