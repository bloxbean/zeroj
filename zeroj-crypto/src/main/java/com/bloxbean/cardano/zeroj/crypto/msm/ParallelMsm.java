package com.bloxbean.cardano.zeroj.crypto.msm;

import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG1BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381;
import com.bloxbean.cardano.zeroj.bls12381.ec.JacobianG2BLS381.AffineG2;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Multi-core MSM combinator (ADR-0029 M5b). Profiling the real 19M-constraint derivation prove
 * showed it running on <b>one</b> of 12 cores — the five MSMs dominate prove time and each ran
 * single-threaded. An MSM is a sum, so it splits perfectly: chunk the points across cores, run the
 * <em>base</em> backend on each chunk concurrently, and add the partial results. Point addition is
 * associative, so the affine result — and therefore the proof — is bit-identical to the serial path.
 *
 * <p>Wraps any backend: the pure-Java flat Pippenger and the FFM-blst binding both get parallelized
 * the same way (for blst, each chunk is its own native call with its own confined arena, and the
 * per-chunk point conversion parallelizes with it).</p>
 */
public final class ParallelMsm {

    private ParallelMsm() {}

    /** Below this size a parallel fan-out costs more than it saves — run the base backend directly. */
    private static final int MIN_PARALLEL = 1 << 15;

    /** Points per chunk floor, so tiny chunks don't drown in per-call overhead. */
    private static final int MIN_CHUNK = 1 << 13;

    static int chunks(int n) {
        int cores = Runtime.getRuntime().availableProcessors();
        return Math.max(1, Math.min(cores, n / MIN_CHUNK));
    }

    /** Parallel wrapper around a G1 MSM backend. */
    public static G1MsmBackend parallel(G1MsmBackend base) {
        return (reader, n, scalars) -> {
            int t = chunks(n);
            if (n < MIN_PARALLEL || t < 2) return base.msm(reader, n, scalars);
            int per = (n + t - 1) / t;
            JacobianG1BLS381[] partial = new JacobianG1BLS381[t];
            java.util.stream.IntStream.range(0, t).parallel().forEach(k -> {
                int lo = k * per, hi = Math.min(n, lo + per);
                if (lo >= hi) { partial[k] = JacobianG1BLS381.INFINITY; return; }
                partial[k] = base.msm(offset(reader, lo), hi - lo,
                        Arrays.copyOfRange(scalars, lo, hi));
            });
            JacobianG1BLS381 acc = JacobianG1BLS381.INFINITY;
            for (JacobianG1BLS381 p : partial) acc = acc.add(p);
            return acc;
        };
    }

    /** Parallel wrapper around a G2 MSM backend. */
    public static G2MsmBackend parallel(G2MsmBackend base) {
        return (points, scalars, n) -> {
            int t = chunks(n);
            if (n < MIN_PARALLEL || t < 2) return base.msm(points, scalars, n);
            int per = (n + t - 1) / t;
            JacobianG2BLS381[] partial = new JacobianG2BLS381[t];
            java.util.stream.IntStream.range(0, t).parallel().forEach(k -> {
                int lo = k * per, hi = Math.min(n, lo + per);
                if (lo >= hi) { partial[k] = JacobianG2BLS381.INFINITY; return; }
                BigInteger[] sc = Arrays.copyOfRange(scalars, lo, hi);
                partial[k] = base.msm(offset(points, lo), sc, hi - lo);
            });
            JacobianG2BLS381 acc = JacobianG2BLS381.INFINITY;
            for (JacobianG2BLS381 p : partial) acc = acc.add(p);
            return acc;
        };
    }

    /** A view of {@code reader} shifted by {@code lo} — chunk k sees indices 0..len-1. */
    private static PippengerFlatBLS381.G1AffineReader offset(PippengerFlatBLS381.G1AffineReader r, int lo) {
        return new PippengerFlatBLS381.G1AffineReader() {
            public int count() { return r.count() - lo; }
            public void readInto(int i, long[] buf) { r.readInto(lo + i, buf); }
        };
    }

    /** A view of {@code reader} shifted by {@code lo} — chunk k sees indices 0..len-1. */
    private static G2AffineReader offset(G2AffineReader r, int lo) {
        return new G2AffineReader() {
            public int count() { return r.count() - lo; }
            public AffineG2 get(int i) { return r.get(lo + i); }
            public void readBE(int i, byte[] dst, int off) { r.readBE(lo + i, dst, off); }
        };
    }
}
