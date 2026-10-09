package org.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.zeroj.bls12381.field.MontFr381;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link FastJubjubPoint} against {@link JubjubPoint}, which stays the oracle. The fast path is
 * used for public data only (subgroup checks, sums, the discrete-log search), so its results
 * must equal the BigInteger path on every input, torsion points included.
 */
class FastJubjubPointTest {

    private static final JubjubPoint G = JubjubPoint.SUBGROUP_GENERATOR;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final JubjubPoint ORDER_2 = JubjubPoint.fromAffine(
            BigInteger.ZERO, JubjubCurve.BASE_FIELD_PRIME.subtract(BigInteger.ONE));
    /** {@code [l]·G_full} has order 8. */
    private static final JubjubPoint ORDER_8 = JubjubPoint.FULL_GENERATOR.scalarMul(L);

    private static BigInteger random(Random rnd, int bits) {
        return new BigInteger(bits, rnd);
    }

    private static void assertSameRepresentative(JubjubPoint expected, FastJubjubPoint actual) {
        assertEquals(expected.u(), actual.u.toBigInteger(), "U");
        assertEquals(expected.v(), actual.v.toBigInteger(), "V");
        assertEquals(expected.z(), actual.z.toBigInteger(), "Z");
        assertEquals(expected.t(), actual.t.toBigInteger(), "T");
    }

    @Test
    @DisplayName("add, doubled and negate give the same projective representative as JubjubPoint")
    void addAndDoubleMatchExactly() {
        Random rnd = new Random(52);
        List<JubjubPoint> points = new ArrayList<>(List.of(
                JubjubPoint.IDENTITY, G, ORDER_2, ORDER_8, JubjubPoint.FULL_GENERATOR));
        for (int i = 0; i < 12; i++) {
            points.add(G.scalarMul(random(rnd, 252)).add(ORDER_8.scalarMul(BigInteger.valueOf(i))));
        }
        for (JubjubPoint p : points) {
            FastJubjubPoint fp = FastJubjubPoint.of(p);
            assertSameRepresentative(p.doubled(), fp.doubled());
            assertSameRepresentative(p.negate(), fp.negate());
            for (JubjubPoint q : points) {
                assertSameRepresentative(p.add(q), fp.add(FastJubjubPoint.of(q)));
            }
        }
    }

    @Test
    @DisplayName("Public scalar multiplication equals JubjubPoint.scalarMul, including k = 0 and k = l")
    void scalarMulMatches() {
        Random rnd = new Random(53);
        List<BigInteger> scalars = new ArrayList<>(List.of(
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO, L, L.subtract(BigInteger.ONE),
                L.add(BigInteger.ONE), BigInteger.ONE.shiftLeft(252).subtract(BigInteger.ONE)));
        for (int i = 0; i < 16; i++) {
            scalars.add(random(rnd, 1 + rnd.nextInt(256)));
        }
        for (JubjubPoint base : List.of(G, JubjubPoint.FULL_GENERATOR, ORDER_8, ORDER_2)) {
            for (BigInteger k : scalars) {
                FastJubjubPoint fast = FastJubjubPoint.of(base).scalarMulPublic(k);
                assertTrue(base.scalarMul(k).projectiveEquals(fast.toJubjubPoint()), "k=" + k);
            }
        }
        for (long k : new long[]{0, 1, 2, 3, 4095, Long.MAX_VALUE}) {
            assertTrue(G.scalarMul(BigInteger.valueOf(k))
                    .projectiveEquals(FastJubjubPoint.GENERATOR.scalarMulPublic(k).toJubjubPoint()));
        }
        assertThrows(IllegalArgumentException.class,
                () -> FastJubjubPoint.GENERATOR.scalarMulPublic(BigInteger.ONE.negate()));
        assertThrows(IllegalArgumentException.class, () -> FastJubjubPoint.GENERATOR.scalarMulPublic(-1L));
    }

    @Test
    @DisplayName("Subgroup check agrees with JubjubPoint.isInSubgroup on subgroup and torsion points")
    void subgroupCheckMatches() {
        Random rnd = new Random(54);
        assertTrue(FastJubjubPoint.isInPrimeOrderSubgroup(JubjubPoint.IDENTITY));
        assertTrue(FastJubjubPoint.isInPrimeOrderSubgroup(G));
        assertFalse(FastJubjubPoint.isInPrimeOrderSubgroup(ORDER_2));
        assertFalse(FastJubjubPoint.isInPrimeOrderSubgroup(ORDER_8));
        assertFalse(FastJubjubPoint.isInPrimeOrderSubgroup(JubjubPoint.FULL_GENERATOR));
        for (int i = 0; i < 8; i++) {
            JubjubPoint p = G.scalarMul(random(rnd, 252)).add(ORDER_8.scalarMul(BigInteger.valueOf(i)));
            assertEquals(p.isInSubgroup(), FastJubjubPoint.isInPrimeOrderSubgroup(p), "torsion index " + i);
        }
    }

    @Test
    @DisplayName("Projective equality, identity test and round trip to JubjubPoint")
    void equalityAndRoundTrip() {
        FastJubjubPoint g = FastJubjubPoint.GENERATOR;
        FastJubjubPoint scaled = g.add(g).add(g).subtract(g).subtract(g);
        assertTrue(scaled.projectiveEquals(g));
        assertFalse(g.projectiveEquals(g.doubled()));
        assertTrue(g.subtract(g).isIdentity());
        assertFalse(g.isIdentity());
        assertTrue(G.projectiveEquals(scaled.toJubjubPoint()));
        assertTrue(JubjubPoint.IDENTITY.projectiveEquals(FastJubjubPoint.IDENTITY.toJubjubPoint()));
        assertTrue(G.add(G).projectiveEquals(FastJubjubPoint.sum(List.of(G, G))));
    }

    @Test
    @DisplayName("Batch inversion inverts every element and refuses a zero element")
    void batchInvert() {
        Random rnd = new Random(55);
        int n = 37;
        MontFr381[] zs = new MontFr381[n];
        MontFr381[] original = new MontFr381[n];
        for (int i = 0; i < n; i++) {
            zs[i] = MontFr381.fromBigInteger(random(rnd, 254).add(BigInteger.ONE));
            original[i] = zs[i];
        }
        FastJubjubPoint.batchInvert(zs, n, new MontFr381[n]);
        for (int i = 0; i < n; i++) {
            assertTrue(original[i].mul(zs[i]).isOne(), "element " + i);
        }
        MontFr381[] withZero = {MontFr381.ONE, MontFr381.ZERO, MontFr381.ONE};
        assertThrows(IllegalStateException.class,
                () -> FastJubjubPoint.batchInvert(withZero, 3, new MontFr381[3]));
    }
}
