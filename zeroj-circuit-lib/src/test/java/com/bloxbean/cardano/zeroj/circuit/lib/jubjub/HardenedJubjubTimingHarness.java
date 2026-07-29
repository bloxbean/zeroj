package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Diagnostic Welch-test harness. A clean result is evidence only for this run/platform. The
 * deliberately leaky control is the sole asserted timing property.
 */
@EnabledIfSystemProperty(named = "zeroj.hardenedTiming", matches = "true")
class HardenedJubjubTimingHarness {

    private static final int WARMUP =
            Integer.getInteger("zeroj.hardenedTimingWarmup", 2_000);
    private static final int SAMPLES =
            Integer.getInteger("zeroj.hardenedTimingSamples", 12_000);
    private static volatile long sink;

    @Test
    void recordTimingSignalsAndDetectNegativeControl() {
        System.out.println("timing platform: " + System.getProperty("java.vm.name") + " "
                + System.getProperty("java.vm.version") + ", "
                + System.getProperty("os.name") + "/" + System.getProperty("os.arch"));

        long[] generator = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.generator(generator, 0);
        long[] low = fr(BigInteger.ONE);
        long[] high = fr(JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE));
        double pointT = measure("point scalar 1 vs l-1",
                () -> scalarMul(generator, low),
                () -> scalarMul(generator, high));

        long[] message = fq(BigInteger.valueOf(123));
        double nonceT = measure("Poseidon sk=1 vs sk=l-1",
                () -> deterministicNonce(low, message),
                () -> deterministicNonce(high, message));

        byte[] auxA = new byte[32];
        byte[] auxB = new byte[32];
        Arrays.fill(auxB, (byte) 0xff);
        long[] nonceKey = new long[4];
        CtJubjubNonce.deriveNonceKey(
                nonceKey, 0, low, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);
        long[] publicKey = publicKey(low);
        double hedgeT = measure("hedged aux=00 vs ff",
                () -> hedgedNonce(nonceKey, publicKey, message, auxA),
                () -> hedgedNonce(nonceKey, publicKey, message, auxB));

        double negativeT = measure("deliberately leaky negative control",
                () -> leaky(8),
                () -> leaky(2_048));
        System.out.printf("summary |t|: point=%.3f nonce=%.3f hedge=%.3f control=%.3f%n",
                Math.abs(pointT), Math.abs(nonceT), Math.abs(hedgeT),
                Math.abs(negativeT));
        assertTrue(Math.abs(negativeT) > 10.0,
                "timing harness failed to detect its deliberately leaky control");
    }

    private static double measure(String name, Runnable classA, Runnable classB) {
        for (int i = 0; i < WARMUP; i++) {
            classA.run();
            classB.run();
        }
        long[] a = new long[SAMPLES];
        long[] b = new long[SAMPLES];
        Random order = new Random(0x39000000L + name.hashCode());
        for (int i = 0; i < SAMPLES; i++) {
            boolean aFirst = order.nextBoolean();
            if (aFirst) {
                a[i] = time(classA);
                b[i] = time(classB);
            } else {
                b[i] = time(classB);
                a[i] = time(classA);
            }
        }
        Stats as = stats(a);
        Stats bs = stats(b);
        double t = (as.mean - bs.mean)
                / Math.sqrt(as.variance / a.length + bs.variance / b.length);
        System.out.printf("%-36s A=%9.2f ns B=%9.2f ns t=%9.3f%n",
                name, as.mean, bs.mean, t);
        return t;
    }

    private static long time(Runnable operation) {
        long start = System.nanoTime();
        operation.run();
        return System.nanoTime() - start;
    }

    private static void scalarMul(long[] generator, long[] scalar) {
        long[] out = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.scalarMul(
                out, 0, generator, 0, scalar, 0,
                new long[CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS], 0);
        sink ^= out[0];
    }

    private static void deterministicNonce(long[] secret, long[] message) {
        long[] out = new long[4];
        CtJubjubNonce.deterministicV1(
                out, 0, secret, 0, message, 0,
                new long[CtJubjubNonce.WORK_LIMBS], 0);
        sink ^= out[0];
    }

    private static void hedgedNonce(long[] nonceKey, long[] publicKey,
                                    long[] message, byte[] auxiliary) {
        long[] out = new long[4];
        CtJubjubNonce.hedgedV1(
                out, 0, nonceKey, 0, publicKey, 0, message, 0,
                auxiliary, 0, new long[CtJubjubNonce.WORK_LIMBS], 0);
        sink ^= out[0];
    }

    private static void leaky(int iterations) {
        long value = sink;
        for (int i = 0; i < iterations; i++) {
            value = value * 0x9e3779b97f4a7c15L + i;
        }
        sink = value;
    }

    private static long[] publicKey(long[] scalar) {
        long[] generator = new long[CtJubjubPointOps.POINT_LIMBS];
        long[] point = new long[CtJubjubPointOps.POINT_LIMBS];
        long[] normalized = new long[CtJubjubPointOps.POINT_LIMBS];
        CtJubjubPointOps.generator(generator, 0);
        CtJubjubPointOps.scalarMul(
                point, 0, generator, 0, scalar, 0,
                new long[CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS], 0);
        CtJubjubPointOps.normalize(
                normalized, 0, point, 0, new long[32], 0);
        return normalized;
    }

    private static long[] fq(BigInteger value) {
        long[] out = new long[4];
        CtJubjubFqOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[8], 0);
        return out;
    }

    private static long[] fr(BigInteger value) {
        long[] out = new long[4];
        CtJubjubFrOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[8], 0);
        return out;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length == 33 && raw[0] == 0 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }

    private static Stats stats(long[] samples) {
        double mean = 0.0;
        for (long sample : samples) {
            mean += sample;
        }
        mean /= samples.length;
        double variance = 0.0;
        for (long sample : samples) {
            double difference = sample - mean;
            variance += difference * difference;
        }
        variance /= samples.length - 1;
        return new Stats(mean, variance);
    }

    private record Stats(double mean, double variance) {
    }
}
