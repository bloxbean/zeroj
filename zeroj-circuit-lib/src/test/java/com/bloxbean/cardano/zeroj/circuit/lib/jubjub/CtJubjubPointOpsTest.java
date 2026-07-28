package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * ADR-0039 M3 differential and invariant tests for the fixed-limb point kernel.
 */
class CtJubjubPointOpsTest {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final SecureRandom RANDOM = new SecureRandom();

    @Test
    @DisplayName("fixed generator and Pedersen H match the existing public constants")
    void constantsMatch() {
        long[] point = new long[16];
        CtJubjubPointOps.generator(point, 0);
        assertEquals(JubjubPoint.SUBGROUP_GENERATOR, toPublic(point));
        assertEquals(-1L, wellFormed(point));

        CtJubjubPointOps.pedersenH(point, 0);
        assertEquals(PedersenCommitment.H, toPublic(point));
        assertEquals(-1L, wellFormed(point));
    }

    @Test
    @DisplayName("complete add, double and negate agree with JubjubPoint")
    void groupOperationsAgree() {
        for (int i = 0; i < 100; i++) {
            BigInteger a = randomScalar();
            BigInteger b = randomScalar();
            JubjubPoint pa = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(a);
            JubjubPoint pb = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(b);
            long[] fixedA = fromPublic(pa);
            long[] fixedB = fromPublic(pb);
            long[] out = new long[16];
            long[] work = new long[128];

            CtJubjubPointOps.add(out, 0, fixedA, 0, fixedB, 0, work, 0);
            assertEquals(pa.add(pb), toPublic(out));
            assertEquals(-1L, wellFormed(out));

            CtJubjubPointOps.doublePoint(out, 0, fixedA, 0, work, 0);
            assertEquals(pa.doubled(), toPublic(out));
            assertEquals(-1L, wellFormed(out));

            CtJubjubPointOps.negate(out, 0, fixedA, 0);
            assertEquals(pa.negate(), toPublic(out));
            assertEquals(-1L, wellFormed(out));
        }
    }

    @Test
    @DisplayName("fixed 252-iteration scalar multiplication agrees on boundaries and random scalars")
    void scalarMultiplicationAgrees() {
        BigInteger[] boundaries = {
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                BigInteger.ONE.shiftLeft(64), BigInteger.ONE.shiftLeft(128),
                BigInteger.ONE.shiftLeft(251), L.subtract(BigInteger.ONE)
        };
        for (BigInteger scalar : boundaries) {
            assertScalarMul(scalar);
        }
        for (int i = 0; i < 40; i++) {
            assertScalarMul(randomScalar());
        }
    }

    @Test
    @DisplayName("identity has no exceptional path and behaves under complete formulas")
    void identityBoundaries() {
        long[] identity = new long[16];
        long[] generator = new long[16];
        long[] out = new long[16];
        long[] work = new long[128];
        CtJubjubPointOps.identity(identity, 0);
        CtJubjubPointOps.generator(generator, 0);

        CtJubjubPointOps.add(out, 0, identity, 0, generator, 0, work, 0);
        assertEquals(JubjubPoint.SUBGROUP_GENERATOR, toPublic(out));
        CtJubjubPointOps.add(out, 0, generator, 0, identity, 0, work, 0);
        assertEquals(JubjubPoint.SUBGROUP_GENERATOR, toPublic(out));
        CtJubjubPointOps.doublePoint(out, 0, identity, 0, work, 0);
        assertEquals(JubjubPoint.IDENTITY, toPublic(out));
        assertEquals(-1L, CtJubjubPointOps.identityMask(identity, 0));
        assertEquals(0L, CtJubjubPointOps.identityMask(generator, 0));
    }

    @Test
    @DisplayName("projective equality and mask selection are representation independent")
    void equalityAndSelection() {
        long[] generator = new long[16];
        long[] doubled = new long[16];
        long[] sum = new long[16];
        long[] selected = new long[16];
        long[] work = new long[128];
        CtJubjubPointOps.generator(generator, 0);
        CtJubjubPointOps.doublePoint(doubled, 0, generator, 0, work, 0);
        CtJubjubPointOps.add(sum, 0, generator, 0, generator, 0, work, 0);

        assertEquals(-1L,
                CtJubjubPointOps.equalMask(doubled, 0, sum, 0, work, 0));
        CtJubjubPointOps.select(selected, 0, doubled, 0, generator, 0, -1L);
        assertEquals(toPublic(doubled), toPublic(selected));
        CtJubjubPointOps.select(selected, 0, doubled, 0, generator, 0, 0L);
        assertEquals(toPublic(generator), toPublic(selected));
    }

    @Test
    @DisplayName("local invariant mask rejects zero-Z, off-curve and broken-T points")
    void invariantMaskRejectsMalformedPoints() {
        long[] zero = new long[16];
        assertEquals(0L, wellFormed(zero));

        long[] generator = new long[16];
        CtJubjubPointOps.generator(generator, 0);
        long[] brokenT = generator.clone();
        CtJubjubFqOps.zero(brokenT, CtJubjubPointOps.T);
        assertEquals(0L, wellFormed(brokenT));

        long[] offCurve = new long[16];
        long[] one = fq(BigInteger.ONE);
        CtJubjubPointOps.fromAffine(offCurve, 0, one, 0, one, 0, new long[8], 0);
        assertEquals(0L, wellFormed(offCurve));
    }

    private static void assertScalarMul(BigInteger scalar) {
        long[] generator = new long[16];
        long[] out = new long[16];
        CtJubjubPointOps.generator(generator, 0);
        CtJubjubPointOps.scalarMul(
                out, 0, generator, 0, fr(scalar), 0,
                new long[CtJubjubPointOps.SCALAR_MUL_WORK_LIMBS], 0);
        assertEquals(JubjubPoint.SUBGROUP_GENERATOR.scalarMul(scalar), toPublic(out),
                "scalar=" + scalar);
        assertEquals(-1L, wellFormed(out));
    }

    private static long wellFormed(long[] point) {
        return CtJubjubPointOps.wellFormedMask(point, 0, new long[64], 0);
    }

    private static long[] fromPublic(JubjubPoint point) {
        long[] u = fq(point.affineU());
        long[] v = fq(point.affineV());
        long[] out = new long[16];
        CtJubjubPointOps.fromAffine(out, 0, u, 0, v, 0, new long[8], 0);
        return out;
    }

    private static JubjubPoint toPublic(long[] point) {
        long[] normalized = new long[16];
        long[] work = new long[64];
        CtJubjubPointOps.normalize(normalized, 0, point, 0, work, 0);
        byte[] u = new byte[32];
        byte[] v = new byte[32];
        CtJubjubFqOps.toCanonicalBytes(u, 0, normalized, CtJubjubPointOps.U, work, 0);
        CtJubjubFqOps.toCanonicalBytes(v, 0, normalized, CtJubjubPointOps.V, work, 0);
        return JubjubPoint.fromAffine(new BigInteger(1, u), new BigInteger(1, v));
    }

    private static long[] fq(BigInteger value) {
        long[] out = new long[4];
        assertEquals(-1L, CtJubjubFqOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[8], 0));
        return out;
    }

    private static long[] fr(BigInteger value) {
        long[] out = new long[4];
        assertEquals(-1L, CtJubjubFrOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[8], 0));
        return out;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int start = raw.length > 32 ? 1 : 0;
        System.arraycopy(raw, start, out, 32 - (raw.length - start), raw.length - start);
        return out;
    }

    private static BigInteger randomScalar() {
        BigInteger value;
        do {
            value = new BigInteger(L.bitLength(), RANDOM);
        } while (value.compareTo(L) >= 0);
        return value;
    }
}
