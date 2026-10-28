package org.zeroj.bls12381.ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Scalar blinding and the test seams shared by the G1 and G2 secret ladders (ADR-0062 D1).
 *
 * <p>A secret scalar {@code k ∈ [0, r)} is replaced by {@code k̂ = k + m·r} with a fresh blinding
 * factor {@code m} drawn uniformly from {@code [M_MIN, M_MAX] = [⌈2³¹⁹/r⌉, ⌊(2³²⁰ − r)/r⌋]}. That
 * range guarantees {@code k̂ ∈ [2³¹⁹, 2³²⁰)} for every {@code k ∈ [0, r)}: the top bit is always bit
 * 319, with no branch on {@code k}, so the ladder runs exactly {@value #ITERATIONS} iterations
 * from {@code (P, 2P)}. {@code [k̂]P = [k]P} holds only for {@code P} in the prime-order subgroup,
 * so callers must check the base first.</p>
 *
 * <p>Blinding also changes the per-bit pattern the ladder replays on every call, which defeats
 * averaging across repeated use of one key (the residual ADR-0038 P7.2 blinded for Jubjub). The
 * range holds about 2^64.1 values, so each call takes about 64 bits of fresh entropy. {@code m} is
 * drawn by rejection sampling of 65-bit values; the rejection branches on public randomness only.
 * A failure of the randomness source propagates: there is no unblinded fallback.</p>
 */
final class SecretLadder {

    private SecretLadder() {}

    /** Bit length of every blinded scalar. */
    static final int WIDTH = 320;

    /** Ladder iterations after the fixed top bit. */
    static final int ITERATIONS = WIDTH - 1;

    private static final BigInteger R = G1Point.R;
    private static final BigInteger LOW = BigInteger.ONE.shiftLeft(WIDTH - 1);
    private static final BigInteger HIGH = BigInteger.ONE.shiftLeft(WIDTH);

    /** {@code ⌈2³¹⁹ / r⌉}. */
    static final BigInteger M_MIN = LOW.add(R).subtract(BigInteger.ONE).divide(R);

    /** {@code ⌊(2³²⁰ − r) / r⌋}. */
    static final BigInteger M_MAX = HIGH.subtract(R).divide(R);

    private static final BigInteger M_RANGE = M_MAX.subtract(M_MIN).add(BigInteger.ONE);
    private static final int SAMPLE_BITS = M_RANGE.bitLength();
    private static final int SAMPLE_BYTES = (SAMPLE_BITS + 7) / 8;

    static {
        // The range must map every k in [0, r) into [2^319, 2^320); fail class init otherwise.
        if (M_MIN.multiply(R).compareTo(LOW) < 0
                || M_MAX.multiply(R).add(R).subtract(BigInteger.ONE).compareTo(HIGH) >= 0
                || M_RANGE.signum() <= 0) {
            throw new IllegalStateException("ADR-0062 D1 blinding range is inconsistent");
        }
    }

    /** Supplies blinding factors; package-private so tests can inject a seeded source. */
    @FunctionalInterface
    interface BlindingSource {
        /** Returns a blinding factor in {@code [M_MIN, M_MAX]}. */
        BigInteger nextBlindingFactor();
    }

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandom::new);

    /** Production source: uniform over {@code [M_MIN, M_MAX]} from {@link SecureRandom}. */
    static final BlindingSource SECURE = () -> sample(RANDOM.get());

    /** Uniform {@code m ∈ [M_MIN, M_MAX]} by rejection sampling of {@code SAMPLE_BITS}-bit values. */
    static BigInteger sample(SecureRandom random) {
        byte[] bytes = new byte[SAMPLE_BYTES];
        try {
            while (true) {
                random.nextBytes(bytes);
                BigInteger m = candidate(bytes);
                if (m != null) {
                    return m;
                }
            }
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** Number of random bytes per rejection-sampling candidate. */
    static final int CANDIDATE_BYTES = SAMPLE_BYTES;

    /**
     * Masks {@code bytes} (big-endian, {@value #CANDIDATE_BYTES} bytes) to {@code SAMPLE_BITS}
     * bits and returns {@code M_MIN + u}, or {@code null} if {@code u} is outside the range and must
     * be rejected. Package-private so the mask and acceptance boundary can be tested directly.
     */
    static BigInteger candidate(byte[] bytes) {
        bytes[0] &= (byte) ((1 << (SAMPLE_BITS - 8 * (SAMPLE_BYTES - 1))) - 1);
        BigInteger u = new BigInteger(1, bytes);
        return u.compareTo(M_RANGE) < 0 ? M_MIN.add(u) : null;
    }

    /**
     * Returns {@code k + m·r} for a fresh {@code m} from {@code source}.
     *
     * @param k a reduced scalar, {@code 0 <= k < r}
     * @throws IllegalStateException if the source returns a factor outside {@code [M_MIN, M_MAX]}
     */
    static BigInteger blind(BigInteger k, BlindingSource source) {
        BigInteger m = Objects.requireNonNull(source.nextBlindingFactor(), "blinding factor");
        if (m.compareTo(M_MIN) < 0 || m.compareTo(M_MAX) > 0) {
            throw new IllegalStateException("Blinding factor outside [M_MIN, M_MAX]");
        }
        ScheduleObserver observer = OBSERVER.get();
        if (observer != null) observer.blindingFactor(m);
        BigInteger kHat = k.add(m.multiply(R));
        if (kHat.bitLength() != WIDTH) { // unreachable for 0 <= k < r; fail closed regardless
            throw new IllegalStateException("Blinded scalar is not " + WIDTH + " bits");
        }
        return kHat;
    }

    // ---- operation-schedule observer (test seam, ADR-0062 I2) ----

    /**
     * Records the ladder's operation schedule. {@link #specialCase} is reported whenever an
     * iteration's inputs or sum is the identity, i.e. whenever {@code add} or {@code doublePoint}
     * would take an early-return branch instead of the general formula.
     */
    interface ScheduleObserver {
        void scheduleStarted(int iterations);

        void addition();

        void doubling();

        void specialCase(int bitIndex);

        /** The blinding factor drawn for this call (lets tests check production randomness). */
        default void blindingFactor(BigInteger m) {}
    }

    private static final ThreadLocal<ScheduleObserver> OBSERVER = new ThreadLocal<>();

    static ScheduleObserver observer() {
        return OBSERVER.get();
    }

    static void installObserverForTesting(ScheduleObserver observer) {
        if (OBSERVER.get() != null) {
            throw new IllegalStateException("a schedule observer is already installed");
        }
        OBSERVER.set(Objects.requireNonNull(observer));
    }

    static void clearObserverForTesting() {
        OBSERVER.remove();
    }
}
