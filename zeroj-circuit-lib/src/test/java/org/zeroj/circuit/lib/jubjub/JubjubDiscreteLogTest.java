package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.OptionalLong;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The bounded discrete-log search ({@code elgamal-jubjub-v1} §6.3, ADR-0052 Q4). */
class JubjubDiscreteLogTest {

    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;

    private static JubjubPoint pointOf(long t) {
        return G.scalarMul(BigInteger.valueOf(t));
    }

    @Test
    @DisplayName("Linear range: finds every t in [0, bound] and nothing above it")
    void linearRange() {
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(100);
        for (long t = 0; t <= 100; t++) {
            assertEquals(OptionalLong.of(t), table.solve(pointOf(t), 100), "t=" + t);
        }
        assertEquals(OptionalLong.empty(), table.solve(pointOf(101), 100));
        assertEquals(OptionalLong.empty(), table.solve(pointOf(50), 49));
    }

    @Test
    @DisplayName("Baby-step giant-step: block edges, both signs, the bound itself and one past it")
    void bsgsEdges() {
        long bound = 1_000_003;
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(bound);
        long m = (long) Math.floor(Math.sqrt((bound + 1) / 2.0)) + 1;
        long stride = 2 * m + 1;
        long[] probes = {0, 1, m - 1, m, m + 1, 2 * m, stride, stride + m, 3 * stride - 1,
                bound - 1, bound, 4096, 4095, 123_456};
        for (long t : probes) {
            assertEquals(OptionalLong.of(t), table.solve(pointOf(t), bound), "t=" + t);
        }
        assertEquals(OptionalLong.empty(), table.solve(pointOf(bound + 1), bound));
        assertEquals(OptionalLong.empty(), table.solve(pointOf(bound + 5_000_000), bound));
        // A smaller bound on the same table: the giant-step loop stops at the requested bound.
        assertEquals(OptionalLong.of(5000), table.solve(pointOf(5000), 5000));
        assertEquals(OptionalLong.empty(), table.solve(pointOf(5001), 5000));
    }

    @Test
    @DisplayName("Random targets up to 2^32 are found exactly")
    void randomLarge() {
        long bound = (1L << 32) - 1;
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(bound);
        Random rnd = new Random(56);
        for (int i = 0; i < 6; i++) {
            long t = rnd.nextLong() & bound;
            assertEquals(OptionalLong.of(t), table.solve(pointOf(t), bound), "t=" + t);
        }
    }

    @Test
    @DisplayName("A point that is not a small multiple of G is reported absent, never approximated")
    void absentTargets() {
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(100_000);
        assertEquals(OptionalLong.empty(), table.solve(PedersenCommitment.H, 100_000));
        assertEquals(OptionalLong.empty(),
                table.solve(G.scalarMul(JubjubCurve.SUBGROUP_ORDER.subtract(BigInteger.ONE)), 100_000));
    }

    @Test
    @DisplayName("Forced key collisions cost time only: every candidate is confirmed exactly")
    void collisionsAreConfirmed() {
        long bound = 200_000;
        // 4-bit keys: almost every lookup hits many unrelated entries.
        JubjubDiscreteLog table = JubjubDiscreteLog.create(
                bound, JubjubDiscreteLog.DEFAULT_MAX_BABY_STEPS, JubjubDiscreteLog.DEFAULT_MAX_GIANT_STEPS, 0xFL);
        for (long t : new long[]{0, 1, 4096, 77_777, bound}) {
            assertEquals(OptionalLong.of(t), table.solve(pointOf(t), bound), "t=" + t);
        }
        assertEquals(OptionalLong.empty(), table.solve(pointOf(bound + 1), bound));
    }

    @Test
    @DisplayName("Limits are explicit: searches beyond the table or the caps are refused up front")
    void limits() {
        assertThrows(IllegalArgumentException.class, () -> JubjubDiscreteLog.forBound(-1));
        assertThrows(IllegalArgumentException.class, () -> JubjubDiscreteLog.forBound(10, 0, 1));
        assertThrows(IllegalArgumentException.class, () -> JubjubDiscreteLog.forBound(10, 1, 0));
        // 2^40 points cannot be covered by 2^10 baby steps and 2^10 giant steps.
        assertThrows(IllegalArgumentException.class,
                () -> JubjubDiscreteLog.forBound(1L << 40, 1 << 10, 1 << 10));
        JubjubDiscreteLog table = JubjubDiscreteLog.forBound(10_000);
        assertThrows(IllegalArgumentException.class, () -> table.solve(G, 10_001));
        assertThrows(IllegalArgumentException.class, () -> table.solve(G, -1));
        assertTrue(JubjubDiscreteLog.forBound(Long.MAX_VALUE >> 20).maxBound() > 0);
    }

    @Test
    @DisplayName("Custom caps cannot overflow the table size or the search arithmetic (review F11)")
    void customCapsOverflow() {
        // Review F11's counterexample: babySteps + 1 wrapped, giving an empty four-slot table that
        // found neither 0 nor 1. It is now refused before anything is allocated.
        assertThrows(IllegalArgumentException.class,
                () -> JubjubDiscreteLog.forBound(Long.MAX_VALUE, Integer.MAX_VALUE, Long.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> JubjubDiscreteLog.tableCapacity(Integer.MAX_VALUE));
        assertThrows(IllegalArgumentException.class, () -> JubjubDiscreteLog.tableCapacity(0));
        assertEquals(4, JubjubDiscreteLog.tableCapacity(1));
        assertEquals(1 << 19, JubjubDiscreteLog.tableCapacity(JubjubDiscreteLog.DEFAULT_MAX_BABY_STEPS));
        // The largest table: 805,306,366 baby steps in 2^30 slots; one more needs 2^31.
        assertEquals(1 << 30, JubjubDiscreteLog.tableCapacity(805_306_366));
        assertThrows(IllegalArgumentException.class, () -> JubjubDiscreteLog.tableCapacity(805_306_367));
        // A bound whose search would step past Long.MAX_VALUE is refused rather than wrapped.
        assertThrows(IllegalArgumentException.class,
                () -> JubjubDiscreteLog.forBound(Long.MAX_VALUE, 1 << 10, Long.MAX_VALUE));
        // Supported custom caps still find small plaintexts, including 0 and 1.
        JubjubDiscreteLog custom = JubjubDiscreteLog.forBound(1 << 20, 1 << 6, 1 << 16);
        for (long t : new long[]{0, 1, 4095, 4096, 123_457, 1 << 20}) {
            assertEquals(OptionalLong.of(t), custom.solve(pointOf(t), 1 << 20), "t=" + t);
        }
    }
}
