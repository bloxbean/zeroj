package org.zeroj.benchmarks;

import org.zeroj.bls12381.ec.JacobianG1BLS381;
import org.zeroj.bls12381.ec.JacobianG2BLS381;
import org.zeroj.bls12381.ec.JacobianG1BLS381.AffineG1;
import org.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;
import org.zeroj.bls12381.field.MontFr381;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.util.Locale;

/** Single-thread cost sample of the importer's existing predicates, not a full-import benchmark. */
public final class SubgroupImportTiming {
    private static final BigInteger R = MontFr381.modulus();
    private static final int POINTS = 512;
    private static final ThreadMXBean THREADS = ManagementFactory.getThreadMXBean();

    public static void main(String[] args) {
        if (!THREADS.isCurrentThreadCpuTimeSupported()) throw new IllegalStateException("CPU timing unavailable");
        THREADS.setThreadCpuTimeEnabled(true);
        var g1 = new AffineG1[POINTS];
        var g2 = new AffineG2[POINTS];
        for (int i = 0; i < POINTS; i++) {
            // Distinct non-infinity public points; construction excluded from timings.
            var scalar = BigInteger.valueOf(i + 1L);
            g1[i] = JacobianG1BLS381.GENERATOR.scalarMul(scalar).toAffine();
            g2[i] = JacobianG2BLS381.GENERATOR.scalarMul(scalar).toAffine();
        }
        System.out.printf("Java %s; %s %s; %d processors; %d points/group; 3 warmup + 5 measured passes%n",
                System.getProperty("java.runtime.version"), System.getProperty("os.name"),
                System.getProperty("os.arch"), Runtime.getRuntime().availableProcessors(), POINTS);
        for (int pass = -3; pass < 5; pass++) {
            measure("G1", pass, () -> {
                for (var p : g1) {
                    if (!p.isOnCurve() || !JacobianG1BLS381.fromAffine(p.x(), p.y()).scalarMul(R).isInfinity())
                        throw new AssertionError("G1 predicate failed");
                }
            });
            measure("G2", pass, () -> {
                for (var p : g2) {
                    if (!p.isOnCurve() || !JacobianG2BLS381.fromAffine(p.x(), p.y()).scalarMul(R).isInfinity())
                        throw new AssertionError("G2 predicate failed");
                }
            });
        }
    }

    private static void measure(String group, int pass, Runnable predicate) {
        long cpu = THREADS.getCurrentThreadCpuTime();
        long wall = System.nanoTime();
        predicate.run();
        double wallMs = (System.nanoTime() - wall) / 1e6 / POINTS;
        double cpuMs = (THREADS.getCurrentThreadCpuTime() - cpu) / 1e6 / POINTS;
        if (pass >= 0) System.out.printf(Locale.ROOT, "%s pass %d: wall %.4f ms/point; CPU %.4f ms/point%n",
                group, pass + 1, wallMs, cpuMs);
    }
}
