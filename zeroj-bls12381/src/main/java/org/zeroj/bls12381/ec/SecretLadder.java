package org.zeroj.bls12381.ec;

import org.zeroj.api.SecureRandoms;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * Additive scalar splitting, fixed-length recoding and the test seams shared by the G1 and G2
 * secret ladders (ADR-0062 D1, r4).
 *
 * <p>A secret scalar {@code k ∈ [0, r)} is split into two shares (Clavier–Joye, CHES 2001):
 * {@code k₁} drawn uniformly from {@code [0, r)} with {@link SecureRandom}, and
 * {@code k₂ = (k − k₁) mod r}. Each share is uniform on its own whatever {@code k} is, so each ladder
 * sees a fresh uniform scalar on every call: a small or near-{@code r} secret no longer drives the
 * ladder through identity intermediates. {@code [k]P = [k₁]P + [k₂]P}.</p>
 *
 * <p>Each share {@code s} is recoded deterministically to {@code ŝ = 2²⁵⁵ + ((s − 2²⁵⁵) mod r)}.
 * Because {@code r < 2²⁵⁵}, {@code ŝ ∈ [2²⁵⁵, 2²⁵⁵ + r)}: the top bit is always bit 255, with no
 * branch on {@code s}, and {@code ŝ ≡ s (mod r)}. The ladder runs exactly {@value #ITERATIONS}
 * iterations from {@code (P, 2P)}. {@code [ŝ]P = [s]P} holds only for {@code P} in the prime-order
 * subgroup, so callers must check the base first.</p>
 *
 * <p>The r1–r3 version instead blinded {@code k} as {@code k + m·r} with a 64-bit {@code m}. That
 * randomises the high bits but not the bottom of the scalar: when {@code 2^i} divides {@code m}, the
 * ladder prefix at step {@code i} reduces to {@code ⌊k/2^i⌋ mod r}, which is 0 for small {@code k}
 * (ADR-0062 F12). With the split the blinding adds cost without protection, so it is dropped.</p>
 *
 * <p>{@code k₁} is drawn by rejection sampling of 255-bit values, which branches on public
 * randomness only. A failure of the randomness source propagates: there is no unsplit fallback.</p>
 */
final class SecretLadder {

    private SecretLadder() {}

    /** Bit length of every recoded share. */
    static final int WIDTH = 256;

    /** Ladder iterations after the fixed top bit, per share. */
    static final int ITERATIONS = WIDTH - 1;

    private static final BigInteger R = G1Point.R;
    private static final BigInteger TOP = BigInteger.ONE.shiftLeft(WIDTH - 1);
    private static final int SAMPLE_BYTES = 32;

    static {
        // The recoding needs r < 2^255, so that 2^255 + [0, r) stays below 2^256.
        if (R.compareTo(TOP) >= 0 || R.bitLength() != WIDTH - 1) {
            throw new IllegalStateException("ADR-0062 D1 recoding needs r < 2^255");
        }
    }

    /** Supplies the first share {@code k₁}; package-private so tests can inject a seeded source. */
    @FunctionalInterface
    interface ShareSource {
        /** Returns a share in {@code [0, r)}. */
        BigInteger nextShare();
    }

    private static final ThreadLocal<SecureRandom> RANDOM = ThreadLocal.withInitial(SecureRandoms::create);

    /** Production source: uniform over {@code [0, r)} from {@link SecureRandom}. */
    static final ShareSource SECURE = () -> sample(RANDOM.get());

    /** Uniform {@code k₁ ∈ [0, r)} by rejection sampling of 255-bit values. */
    static BigInteger sample(SecureRandom random) {
        byte[] bytes = new byte[SAMPLE_BYTES];
        try {
            while (true) {
                random.nextBytes(bytes);
                BigInteger k1 = candidate(bytes);
                if (k1 != null) {
                    return k1;
                }
            }
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    /** Number of random bytes per rejection-sampling candidate. */
    static final int CANDIDATE_BYTES = SAMPLE_BYTES;

    /**
     * Masks {@code bytes} (big-endian, {@value #CANDIDATE_BYTES} bytes) to 255 bits and returns the
     * value if it is below {@code r}, or {@code null} if it must be rejected. Package-private so the
     * mask and acceptance boundary can be tested directly.
     */
    static BigInteger candidate(byte[] bytes) {
        bytes[0] &= 0x7f;
        BigInteger u = new BigInteger(1, bytes);
        return u.compareTo(R) < 0 ? u : null;
    }

    /**
     * Returns the two shares {@code {k₁, (k − k₁) mod r}} for a fresh {@code k₁} from {@code source}.
     *
     * @param k a reduced scalar, {@code 0 <= k < r}
     * @throws IllegalStateException if the source returns a share outside {@code [0, r)}
     */
    static BigInteger[] split(BigInteger k, ShareSource source) {
        BigInteger k1 = Objects.requireNonNull(source.nextShare(), "share");
        if (k1.signum() < 0 || k1.compareTo(R) >= 0) {
            throw new IllegalStateException("Share outside [0, r)");
        }
        ScheduleObserver observer = OBSERVER.get();
        if (observer != null) observer.share(k1);
        return new BigInteger[]{k1, k.subtract(k1).mod(R)};
    }

    /** {@code 2²⁵⁵ + ((s − 2²⁵⁵) mod r)}: exactly 256 bits and {@code ≡ s (mod r)}. */
    static BigInteger recode(BigInteger share) {
        BigInteger hat = TOP.add(share.subtract(TOP).mod(R));
        if (hat.bitLength() != WIDTH) { // unreachable for r < 2^255; fail closed regardless
            throw new IllegalStateException("Recoded share is not " + WIDTH + " bits");
        }
        return hat;
    }

    // ---- operation-schedule observer (test seam, ADR-0062 I2) ----

    /**
     * Records the ladders' operation schedule. {@link #specialCase} is reported whenever an
     * iteration's inputs or sum is the identity, i.e. whenever {@code add} or {@code doublePoint}
     * would take an early-return branch instead of the general formula.
     * {@link #combinationSpecial} is reported when the final addition of the two share results takes
     * a special branch (an identity operand, equal operands, or an identity sum).
     */
    interface ScheduleObserver {
        void scheduleStarted(int iterations);

        void addition();

        void doubling();

        void specialCase(int bitIndex);

        /** The final {@code [k₁]P + [k₂]P} takes a special branch. */
        default void combinationSpecial() {}

        /** The first share drawn for this call (lets tests check production randomness). */
        default void share(BigInteger k1) {}
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
