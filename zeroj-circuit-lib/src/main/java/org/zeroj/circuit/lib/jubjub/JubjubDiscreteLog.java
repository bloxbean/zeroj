package org.zeroj.circuit.lib.jubjub;

import org.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Bounded discrete logarithm to the base {@code G} on Jubjub: finds the unique
 * {@code t ∈ [0, bound]} with {@code [t]·G = M}, or reports that none exists
 * ({@code elgamal-jubjub-v1} §6.3; ADR-0052 Q4, decided: baby-step giant-step with explicit
 * limits).
 *
 * <h2>Algorithm</h2>
 * Baby-step giant-step using the symmetry {@code v(−P) = v(P)} of twisted-Edwards points. The
 * table maps the affine {@code v}-coordinate of {@code [j]·G} to {@code j} for
 * {@code j ∈ [0, m]}. Giant step {@code i} looks up {@code Γ_i = M − [c_i]·G} with
 * {@code c_i = m + i·(2m + 1)}. If {@code t ∈ [c_i − m, c_i + m]} then {@code Γ_i = ±[j]·G}
 * for some table entry {@code j}, and the candidates {@code c_i ± j} are tested. The blocks
 * {@code [c_i − m, c_i + m]} tile {@code [0, bound]}, so every {@code t} is reached. Work is
 * about {@code √(2·(bound + 1))} point additions, half the table of the plain algorithm.
 *
 * <p>Correctness does not rest on the table: every candidate is <b>confirmed exactly</b>
 * ({@code [t]·G = M}, projectively) and checked against {@code [0, bound]} before it is
 * returned, so a key collision can only cost time, never produce a wrong answer. The key is a
 * 64-bit mix of the Montgomery limbs of {@code v}, and every slot holding an equal key is
 * probed. Bounds below {@value #LINEAR_THRESHOLD} use a linear scan.
 *
 * <h2>Limits</h2>
 * A table is sized when built and refuses any search beyond {@link #maxBound()}. The defaults
 * ({@value #DEFAULT_MAX_BABY_STEPS} baby steps, about 6 MiB of table, and
 * {@value #DEFAULT_MAX_GIANT_STEPS} giant steps) reach bounds near {@code 2^43}. A table is
 * immutable after construction and can be shared between threads and decryptions.
 *
 * <h2>Timing</h2>
 * The running time depends on {@code t}. When {@code M} is the image of a secret plaintext,
 * the search is part of the compatibility/offline class (ADR-0039 §3.1) like the rest of
 * decryption. It makes no constant-time claim.
 */
public final class JubjubDiscreteLog {

    /** Default cap on the table size. */
    public static final int DEFAULT_MAX_BABY_STEPS = 1 << 18;

    /** Default cap on the number of giant steps per search. */
    public static final long DEFAULT_MAX_GIANT_STEPS = 1L << 24;

    /** Bounds below this use a linear scan without a table. */
    static final int LINEAR_THRESHOLD = 1 << 12;

    private static final int CHUNK = 1024;

    private final long maxBound;
    private final int babySteps;
    private final long stride;
    private final long keyMask;
    private final long[] keys;
    private final int[] values;
    private final int mask;
    private final FastJubjubPoint negCenter;
    private final FastJubjubPoint negStride;

    private JubjubDiscreteLog(long maxBound, int babySteps, long keyMask) {
        this.maxBound = maxBound;
        this.babySteps = babySteps;
        this.keyMask = keyMask;
        if (babySteps == 0) {
            this.stride = 0;
            this.keys = null;
            this.values = null;
            this.mask = 0;
            this.negCenter = null;
            this.negStride = null;
            return;
        }
        this.stride = 2L * babySteps + 1;
        int capacity = tableCapacity(babySteps); // validated in create(), before any allocation
        int entries = babySteps + 1; // ≤ capacity ≤ 2^30, so no overflow
        this.keys = new long[capacity];
        this.values = new int[capacity];
        this.mask = capacity - 1;
        this.negCenter = FastJubjubPoint.GENERATOR.scalarMulPublic(babySteps).negate();
        this.negStride = FastJubjubPoint.GENERATOR.scalarMulPublic(stride).negate();
        buildTable(entries);
    }

    /** A table for bounds up to {@code maxBound}, with the default limits. */
    public static JubjubDiscreteLog forBound(long maxBound) {
        return forBound(maxBound, DEFAULT_MAX_BABY_STEPS, DEFAULT_MAX_GIANT_STEPS);
    }

    /**
     * A table for bounds up to {@code maxBound}.
     *
     * @param maxBound      the largest bound any search with this table may use; {@code ≥ 0}
     * @param maxBabySteps  cap on the table size (memory); {@code ≥ 1}
     * @param maxGiantSteps cap on the giant steps of one search (time); {@code ≥ 1}
     * @throws IllegalArgumentException if {@code maxBound} cannot be searched within the caps
     */
    public static JubjubDiscreteLog forBound(long maxBound, int maxBabySteps, long maxGiantSteps) {
        return create(maxBound, maxBabySteps, maxGiantSteps, -1L);
    }

    /** Test seam: {@code keyMask} truncates table keys to force collisions. */
    static JubjubDiscreteLog create(long maxBound, int maxBabySteps, long maxGiantSteps, long keyMask) {
        if (maxBound < 0) {
            throw new IllegalArgumentException("maxBound must be non-negative");
        }
        if (maxBabySteps < 1 || maxGiantSteps < 1) {
            throw new IllegalArgumentException("search limits must be positive");
        }
        if (maxBound < LINEAR_THRESHOLD) {
            return new JubjubDiscreteLog(maxBound, 0, keyMask);
        }
        BigInteger points = BigInteger.valueOf(maxBound).add(BigInteger.ONE);
        long ideal = points.shiftRight(1).sqrt().longValueExact() + 1;
        int m = (int) Math.min(ideal, maxBabySteps);
        tableCapacity(m); // refuses an unsupported table size up front (review F11)
        long strideLength = 2L * m + 1;
        // A search visits t up to bound + stride − 1, which must not overflow a long.
        if (maxBound > Long.MAX_VALUE - strideLength) {
            throw new IllegalArgumentException("bound " + maxBound + " is too close to Long.MAX_VALUE to search");
        }
        BigInteger giants = points.add(BigInteger.valueOf(strideLength - 1))
                .divide(BigInteger.valueOf(strideLength));
        if (giants.compareTo(BigInteger.valueOf(maxGiantSteps)) > 0) {
            throw new IllegalArgumentException(
                    "bound " + maxBound + " exceeds the search capacity of " + m
                            + " baby steps and " + maxGiantSteps + " giant steps");
        }
        return new JubjubDiscreteLog(maxBound, m, keyMask);
    }

    /**
     * The open-addressing capacity for {@code babySteps + 1} entries at load factor at most 3/4:
     * a power of two, at most {@code 2^30}. Computed in {@code long}, so it is exact for every
     * {@code int} (review F11: {@code babySteps + 1} wrapped for {@code Integer.MAX_VALUE}).
     *
     * @throws IllegalArgumentException if the table would exceed {@code 2^30} slots
     */
    static int tableCapacity(int babySteps) {
        if (babySteps < 1) {
            throw new IllegalArgumentException("babySteps must be positive");
        }
        long entries = babySteps + 1L;
        long wanted = Math.max(4L, entries * 4 / 3 + 1);
        long capacity = Long.highestOneBit(wanted - 1) << 1;
        if (capacity > (1L << 30)) {
            throw new IllegalArgumentException("baby-step table too large: " + babySteps + " baby steps");
        }
        return (int) capacity;
    }

    /** The largest bound this table searches. */
    public long maxBound() {
        return maxBound;
    }

    /**
     * Returns the unique {@code t ∈ [0, bound]} with {@code [t]·G = target}, or empty.
     *
     * @throws IllegalArgumentException if {@code bound} is negative or above {@link #maxBound()}
     */
    public OptionalLong solve(JubjubPoint target, long bound) {
        Objects.requireNonNull(target, "target");
        if (bound < 0 || bound > maxBound) {
            throw new IllegalArgumentException(
                    "bound must be in [0, " + maxBound + "], got " + bound);
        }
        FastJubjubPoint m = FastJubjubPoint.of(target);
        if (babySteps == 0 || bound < LINEAR_THRESHOLD) {
            return linear(m, bound);
        }
        long giants = bound / stride + 1; // ⌈(bound + 1) / stride⌉, without overflow
        FastJubjubPoint gamma = m.add(negCenter);
        FastJubjubPoint[] chunk = new FastJubjubPoint[CHUNK];
        MontFr381[] zs = new MontFr381[CHUNK];
        MontFr381[] scratch = new MontFr381[CHUNK];
        for (long base = 0; base < giants; base += CHUNK) {
            int count = (int) Math.min(CHUNK, giants - base);
            for (int i = 0; i < count; i++) {
                chunk[i] = gamma;
                zs[i] = gamma.z;
                gamma = gamma.add(negStride);
            }
            FastJubjubPoint.batchInvert(zs, count, scratch);
            for (int i = 0; i < count; i++) {
                long key = key(chunk[i].v.mul(zs[i]));
                long center = babySteps + (base + i) * stride;
                long found = probe(key, center, bound, m);
                if (found >= 0) {
                    return OptionalLong.of(found);
                }
            }
        }
        return OptionalLong.empty();
    }

    private OptionalLong linear(FastJubjubPoint m, long bound) {
        FastJubjubPoint running = FastJubjubPoint.IDENTITY;
        for (long t = 0; t <= bound; t++) {
            if (running.projectiveEquals(m)) {
                return OptionalLong.of(t);
            }
            running = running.add(FastJubjubPoint.GENERATOR);
        }
        return OptionalLong.empty();
    }

    /** Tests every table entry with this key; returns the confirmed {@code t} or {@code −1}. */
    private long probe(long key, long center, long bound, FastJubjubPoint m) {
        int index = slot(key);
        while (values[index] != 0) {
            if (keys[index] == key) {
                long j = values[index] - 1L;
                if (confirm(center + j, bound, m)) {
                    return center + j;
                }
                if (j != 0 && confirm(center - j, bound, m)) {
                    return center - j;
                }
            }
            index = (index + 1) & mask;
        }
        return -1;
    }

    private static boolean confirm(long t, long bound, FastJubjubPoint m) {
        if (t < 0 || t > bound) {
            return false;
        }
        return FastJubjubPoint.GENERATOR.scalarMulPublic(t).projectiveEquals(m);
    }

    private void buildTable(int entries) {
        FastJubjubPoint running = FastJubjubPoint.IDENTITY;
        FastJubjubPoint[] chunk = new FastJubjubPoint[CHUNK];
        MontFr381[] zs = new MontFr381[CHUNK];
        MontFr381[] scratch = new MontFr381[CHUNK];
        for (int base = 0; base < entries; base += CHUNK) {
            int count = Math.min(CHUNK, entries - base);
            for (int i = 0; i < count; i++) {
                chunk[i] = running;
                zs[i] = running.z;
                running = running.add(FastJubjubPoint.GENERATOR);
            }
            FastJubjubPoint.batchInvert(zs, count, scratch);
            for (int i = 0; i < count; i++) {
                insert(key(chunk[i].v.mul(zs[i])), base + i);
            }
        }
    }

    private void insert(long key, int j) {
        int index = slot(key);
        while (values[index] != 0) {
            index = (index + 1) & mask;
        }
        keys[index] = key;
        values[index] = j + 1; // 0 marks an empty slot
    }

    private int slot(long key) {
        long h = key * 0x9E3779B97F4A7C15L;
        return (int) (h ^ (h >>> 32)) & mask;
    }

    /** The one key function shared by table build and lookup: a mix of {@code v}'s limbs. */
    private long key(MontFr381 affineV) {
        long[] limbs = affineV.toLimbs();
        long k = limbs[0] ^ Long.rotateLeft(limbs[1], 21) ^ Long.rotateLeft(limbs[2], 42)
                ^ Long.rotateLeft(limbs[3], 63);
        return k & keyMask;
    }
}
