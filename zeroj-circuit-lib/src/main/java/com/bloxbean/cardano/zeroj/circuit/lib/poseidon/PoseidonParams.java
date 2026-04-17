package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Parameter bundle for a specific Poseidon instantiation: scalar field,
 * state width, S-box, round counts, and the {@code (C, M)} pair (round
 * constants and MDS matrix) produced by the authoritative Grain LFSR
 * generator defined in the Poseidon paper (see
 * {@link PoseidonGrainLFSR}).
 *
 * <p>A {@code PoseidonParams} instance is the unit of compatibility: two
 * Poseidon implementations interoperate if and only if they use equal
 * {@code PoseidonParams}. Named presets (e.g. {@code PoseidonParamsBN254T3},
 * {@code PoseidonParamsBLS12_381T3}) are generated from the Grain LFSR at
 * build time via {@link PoseidonParamsCodegen} and committed as source for
 * IDE ergonomics and GraalVM native-image compatibility.
 *
 * <p>Immutability: the arrays {@code c} and {@code m} are cloned on
 * construction and on every accessor call, so callers cannot mutate them.
 * Because the accessor clones are O(n), gadget code on hot paths should
 * prefer {@link #cAt(int, int)} and {@link #mAt(int, int)} which read the
 * internal arrays directly.
 *
 * <p>Equality: {@link #equals(Object)} and {@link #hashCode()} are overridden
 * to compare the arrays by content (via {@link Arrays#equals}). This is
 * critical because Java records' default {@code equals} uses reference
 * equality for array components, which would make two independently
 * constructed identical parameter sets compare unequal.
 *
 * @param field scalar field over which Poseidon operates
 * @param t     state width (number of cells)
 * @param alpha S-box exponent; must be coprime to {@code p - 1} (not checked
 *              here — the known presets BN254 / BLS12-381 with {@code alpha=5}
 *              satisfy this; adding primes where {@code gcd(alpha, p-1) != 1}
 *              requires new analysis)
 * @param rf    full rounds (typically 8)
 * @param rp    partial rounds (depends on field, t, and security target)
 * @param c     round constants, length {@code (rf + rp) * t}, each in {@code [0, field.prime())}
 * @param m     MDS matrix, length {@code t * t}, row-major, each in {@code [0, field.prime())}
 */
public record PoseidonParams(
        FieldConfig field,
        int t,
        int alpha,
        int rf,
        int rp,
        BigInteger[] c,
        BigInteger[] m
) {

    public PoseidonParams {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(c, "c");
        Objects.requireNonNull(m, "m");
        if (t < 2) {
            throw new IllegalArgumentException("t must be >= 2, got " + t);
        }
        if (alpha < 3) {
            throw new IllegalArgumentException("alpha must be >= 3, got " + alpha);
        }
        if (rf < 0 || rp < 0) {
            throw new IllegalArgumentException("rf/rp must be non-negative");
        }
        if (c.length != (rf + rp) * t) {
            throw new IllegalArgumentException(
                    "c.length must be (rf + rp) * t = " + ((rf + rp) * t) + ", got " + c.length);
        }
        if (m.length != t * t) {
            throw new IllegalArgumentException(
                    "m.length must be t * t = " + (t * t) + ", got " + m.length);
        }
        BigInteger prime = field.prime();
        validateElements(c, prime, "c");
        validateElements(m, prime, "m");
        c = c.clone();
        m = m.clone();
    }

    private static void validateElements(BigInteger[] arr, BigInteger prime, String name) {
        for (int i = 0; i < arr.length; i++) {
            BigInteger v = arr[i];
            if (v == null) {
                throw new IllegalArgumentException(name + "[" + i + "] is null");
            }
            if (v.signum() < 0) {
                throw new IllegalArgumentException(name + "[" + i + "] is negative: " + v);
            }
            if (v.compareTo(prime) >= 0) {
                throw new IllegalArgumentException(name + "[" + i + "] >= field prime");
            }
        }
    }

    /** Total round count, {@code rf + rp}. */
    public int totalRounds() {
        return rf + rp;
    }

    /**
     * Defensive copy of the round constants. O(n); in hot paths prefer
     * {@link #cAt(int, int)}.
     */
    @Override
    public BigInteger[] c() {
        return c.clone();
    }

    /**
     * Defensive copy of the MDS matrix (row-major). O(n); in hot paths prefer
     * {@link #mAt(int, int)}.
     */
    @Override
    public BigInteger[] m() {
        return m.clone();
    }

    /** Round constant at round {@code r}, cell {@code i}. */
    public BigInteger cAt(int r, int i) {
        return c[r * t + i];
    }

    /** MDS entry at row {@code i}, column {@code j}. */
    public BigInteger mAt(int i, int j) {
        return m[i * t + j];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PoseidonParams other)) return false;
        return t == other.t
                && alpha == other.alpha
                && rf == other.rf
                && rp == other.rp
                && field.equals(other.field)
                && Arrays.equals(c, other.c)
                && Arrays.equals(m, other.m);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(field, t, alpha, rf, rp);
        result = 31 * result + Arrays.hashCode(c);
        result = 31 * result + Arrays.hashCode(m);
        return result;
    }

    @Override
    public String toString() {
        return "PoseidonParams{field=" + field.name()
                + ", t=" + t + ", alpha=" + alpha
                + ", rf=" + rf + ", rp=" + rp
                + ", |c|=" + c.length + ", |m|=" + m.length + "}";
    }
}
