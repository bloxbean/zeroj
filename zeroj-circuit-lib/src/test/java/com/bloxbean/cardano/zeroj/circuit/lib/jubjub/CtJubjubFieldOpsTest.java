package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * ADR-0039 M1/M2 differential tests for both fixed-limb Montgomery kernels.
 */
class CtJubjubFieldOpsTest {

    private static final BigInteger P = JubjubCurve.BASE_FIELD_PRIME;
    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    /**
     * A reproducible differential corpus is more useful than fresh randomness here: a failure
     * must identify the same carry/borrow case on every rerun. This is test data, not key
     * generation.
     */
    private static final Random RANDOM = new Random(0x39_4649454c44L);

    @Test
    @DisplayName("Fq exhaustive small arithmetic agrees with BigInteger")
    void fqSmallExhaustive() {
        for (int ai = 0; ai < 64; ai++) {
            for (int bi = 0; bi < 64; bi++) {
                assertFqBinary(BigInteger.valueOf(ai), BigInteger.valueOf(bi));
            }
        }
    }

    @Test
    @DisplayName("Fr exhaustive small arithmetic agrees with BigInteger")
    void frSmallExhaustive() {
        for (int ai = 0; ai < 64; ai++) {
            for (int bi = 0; bi < 64; bi++) {
                assertFrBinary(BigInteger.valueOf(ai), BigInteger.valueOf(bi));
            }
        }
    }

    @Test
    @DisplayName("Fq random and boundary arithmetic agrees with BigInteger")
    void fqRandomAndBoundaries() {
        BigInteger[] boundaries = {
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                P.shiftRight(1), P.subtract(BigInteger.TWO), P.subtract(BigInteger.ONE)
        };
        for (BigInteger a : boundaries) {
            for (BigInteger b : boundaries) {
                assertFqBinary(a, b);
            }
        }
        for (int i = 0; i < 2_000; i++) {
            assertFqBinary(randomBelow(P), randomBelow(P));
        }
    }

    @Test
    @DisplayName("Fr random and boundary arithmetic agrees with BigInteger")
    void frRandomAndBoundaries() {
        BigInteger[] boundaries = {
                BigInteger.ZERO, BigInteger.ONE, BigInteger.TWO,
                L.shiftRight(1), L.subtract(BigInteger.TWO), L.subtract(BigInteger.ONE)
        };
        for (BigInteger a : boundaries) {
            for (BigInteger b : boundaries) {
                assertFrBinary(a, b);
            }
        }
        for (int i = 0; i < 2_000; i++) {
            assertFrBinary(randomBelow(L), randomBelow(L));
        }
    }

    @Test
    @DisplayName("limb carry and borrow boundaries agree with BigInteger")
    void limbCarryBorrowBoundaries() {
        for (BigInteger modulus : new BigInteger[]{P, L}) {
            BigInteger[] values = {
                    BigInteger.ZERO,
                    BigInteger.ONE,
                    BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE),
                    BigInteger.ONE.shiftLeft(64),
                    BigInteger.ONE.shiftLeft(64).add(BigInteger.ONE),
                    BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE),
                    BigInteger.ONE.shiftLeft(128),
                    BigInteger.ONE.shiftLeft(192).subtract(BigInteger.ONE),
                    BigInteger.ONE.shiftLeft(192),
                    modulus.subtract(BigInteger.ONE.shiftLeft(128)),
                    modulus.subtract(BigInteger.ONE.shiftLeft(64)),
                    modulus.subtract(BigInteger.TWO),
                    modulus.subtract(BigInteger.ONE)
            };
            for (BigInteger a : values) {
                for (BigInteger b : values) {
                    if (modulus == P) {
                        assertFqBinary(a, b);
                    } else {
                        assertFrBinary(a, b);
                    }
                }
            }
        }
    }

    @Test
    @DisplayName("raw Montgomery limbs propagate an incoming borrow through every limb")
    void rawLimbBorrowPropagation() throws Exception {
        assertRawBorrowPropagation(privateLongArray(CtJubjubFqOps.class, "MODULUS"));
        assertRawBorrowPropagation(privateLongArray(CtJubjubFrOps.class, "MODULUS"));
    }

    @Test
    @DisplayName("field identities and distributivity hold over a reproducible corpus")
    void identitiesAndDistributivity() {
        for (int i = 0; i < 1_024; i++) {
            assertFqProperties(randomBelow(P), randomBelow(P), randomBelow(P));
            assertFrProperties(randomBelow(L), randomBelow(L), randomBelow(L));
        }
    }

    @Test
    @DisplayName("fixed public-exponent inversions agree with BigInteger")
    void inversionsAgree() {
        for (int i = 0; i < 64; i++) {
            BigInteger fqValue = i < 4
                    ? new BigInteger[]{BigInteger.ONE, BigInteger.TWO,
                    P.subtract(BigInteger.TWO), P.subtract(BigInteger.ONE)}[i]
                    : randomNonZeroBelow(P);
            BigInteger frValue = i < 4
                    ? new BigInteger[]{BigInteger.ONE, BigInteger.TWO,
                    L.subtract(BigInteger.TWO), L.subtract(BigInteger.ONE)}[i]
                    : randomNonZeroBelow(L);

            long[] fq = fq(fqValue);
            long[] fqOut = new long[4];
            long[] work = new long[64];
            CtJubjubFqOps.invert(fqOut, 0, fq, 0, work, 0);
            assertEquals(fqValue.modInverse(P), fqValue(fqOut));

            long[] fr = fr(frValue);
            long[] frOut = new long[4];
            Arrays.fill(work, 0L);
            CtJubjubFrOps.invert(frOut, 0, fr, 0, work, 0);
            assertEquals(frValue.modInverse(L), frValue(frOut));
        }
    }

    @Test
    @DisplayName("fixed-schedule inversion defines zero input as zero output")
    void zeroInversionConvention() {
        long[] out = new long[4];
        long[] work = new long[64];
        CtJubjubFqOps.invert(out, 0, fq(BigInteger.ZERO), 0, work, 0);
        assertEquals(BigInteger.ZERO, fqValue(out));

        Arrays.fill(out, -1L);
        Arrays.fill(work, 0L);
        CtJubjubFrOps.invert(out, 0, fr(BigInteger.ZERO), 0, work, 0);
        assertEquals(BigInteger.ZERO, frValue(out));
    }

    @Test
    @DisplayName("all field operations support output aliasing")
    void aliasing() {
        for (int i = 0; i < 200; i++) {
            BigInteger a = randomBelow(P);
            BigInteger b = randomBelow(P);
            long[] expected = new long[4];
            long[] left = fq(a);
            long[] right = fq(b);
            long[] work = new long[32];
            CtJubjubFqOps.mul(expected, 0, left, 0, right, 0, work, 0);

            long[] aliasLeft = left.clone();
            CtJubjubFqOps.mul(aliasLeft, 0, aliasLeft, 0, right, 0, work, 0);
            assertArrayEquals(expected, aliasLeft);

            long[] aliasRight = right.clone();
            CtJubjubFqOps.mul(aliasRight, 0, left, 0, aliasRight, 0, work, 0);
            assertArrayEquals(expected, aliasRight);

            BigInteger af = a.mod(L);
            BigInteger bf = b.mod(L);
            long[] expectedFr = new long[4];
            long[] leftFr = fr(af);
            long[] rightFr = fr(bf);
            CtJubjubFrOps.mul(expectedFr, 0, leftFr, 0, rightFr, 0, work, 0);
            CtJubjubFrOps.mul(leftFr, 0, leftFr, 0, rightFr, 0, work, 0);
            assertArrayEquals(expectedFr, leftFr);
        }
    }

    @Test
    @DisplayName("canonical 32-byte codecs reject modulus and round-trip boundaries")
    void canonicalCodecs() {
        for (BigInteger value : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, P.subtract(BigInteger.ONE)}) {
            long[] out = new long[4];
            long mask = CtJubjubFqOps.fromCanonicalBytes(
                    out, 0, fixed32(value), 0, new long[16], 0);
            assertEquals(-1L, mask);
            assertArrayEquals(fixed32(value), fqBytes(out));
        }
        assertEquals(0L, CtJubjubFqOps.fromCanonicalBytes(
                new long[4], 0, fixed32(P), 0, new long[16], 0));

        for (BigInteger value : new BigInteger[]{
                BigInteger.ZERO, BigInteger.ONE, L.subtract(BigInteger.ONE)}) {
            long[] out = new long[4];
            long mask = CtJubjubFrOps.fromCanonicalBytes(
                    out, 0, fixed32(value), 0, new long[16], 0);
            assertEquals(-1L, mask);
            assertArrayEquals(fixed32(value), frBytes(out));
        }
        assertEquals(0L, CtJubjubFrOps.fromCanonicalBytes(
                new long[4], 0, fixed32(L), 0, new long[16], 0));
    }

    @Test
    @DisplayName("p-to-l reduction covers every quotient and the p-1 boundary")
    void fixedEightRoundReduction() {
        BigInteger delta = P.subtract(L.shiftLeft(3));
        for (int quotient = 0; quotient <= 8; quotient++) {
            BigInteger maxRemainder = quotient == 8
                    ? delta.subtract(BigInteger.ONE)
                    : L.subtract(BigInteger.ONE);
            for (BigInteger remainder : new BigInteger[]{
                    BigInteger.ZERO, BigInteger.ONE, maxRemainder}) {
                BigInteger value = L.multiply(BigInteger.valueOf(quotient)).add(remainder);
                if (value.compareTo(P) >= 0) {
                    continue;
                }
                long[] reduced = new long[4];
                CtJubjubFrOps.reduceFromFq(
                        reduced, 0, fq(value), 0, new long[32], 0);
                assertEquals(value.mod(L), frValue(reduced),
                        "q=" + quotient + ", r=" + remainder);
            }
        }
        long[] reduced = new long[4];
        CtJubjubFrOps.reduceFromFq(reduced, 0, fq(P.subtract(BigInteger.ONE)), 0,
                new long[32], 0);
        assertEquals(P.subtract(BigInteger.ONE).mod(L), frValue(reduced));
    }

    @Test
    @DisplayName("hedged nonzero mapping is exact at all reduction boundaries")
    void fixedNonZeroMapping() {
        BigInteger modulus = L.subtract(BigInteger.ONE);
        for (int quotient = 0; quotient <= 8; quotient++) {
            for (BigInteger remainder : new BigInteger[]{
                    BigInteger.ZERO, BigInteger.ONE, modulus.subtract(BigInteger.ONE)}) {
                BigInteger value = modulus.multiply(BigInteger.valueOf(quotient)).add(remainder);
                if (value.compareTo(P) >= 0) {
                    continue;
                }
                long[] mapped = new long[4];
                CtJubjubFrOps.mapFromFqNonZero(
                        mapped, 0, fq(value), 0, new long[32], 0);
                BigInteger actual = frValue(mapped);
                assertEquals(value.mod(modulus).add(BigInteger.ONE), actual);
                assertNotEquals(BigInteger.ZERO, actual);
            }
        }

        // These residues force the final +1 through one, two, and three complete
        // 64-bit limbs. Reduction-boundary vectors alone do not exercise this carry chain.
        for (int boundary : new int[]{64, 128, 192}) {
            BigInteger input = BigInteger.ONE.shiftLeft(boundary).subtract(BigInteger.ONE);
            long[] mapped = new long[4];
            CtJubjubFrOps.mapFromFqNonZero(
                    mapped, 0, fq(input), 0, new long[32], 0);
            assertEquals(BigInteger.ONE.shiftLeft(boundary), frValue(mapped),
                    "carry through " + (boundary / 64) + " limb(s)");
            assertNotEquals(BigInteger.ZERO, frValue(mapped));
        }

        // Pin both sides of the wrap at q = l-1 explicitly.
        for (BigInteger input : new BigInteger[]{
                L.subtract(BigInteger.TWO), L.subtract(BigInteger.ONE)}) {
            long[] mapped = new long[4];
            CtJubjubFrOps.mapFromFqNonZero(
                    mapped, 0, fq(input), 0, new long[32], 0);
            assertEquals(input.mod(modulus).add(BigInteger.ONE), frValue(mapped));
            assertNotEquals(BigInteger.ZERO, frValue(mapped));
        }
    }

    @Test
    @DisplayName("unsigned-256 scalar reduction covers every quotient and declared width")
    void unsigned256Reduction() {
        BigInteger limit = BigInteger.ONE.shiftLeft(256);
        BigInteger maxQuotient = limit.subtract(BigInteger.ONE).divide(L);
        assertEquals(BigInteger.valueOf(17), maxQuotient);
        for (int quotient = 0; quotient <= 17; quotient++) {
            BigInteger largest = limit.subtract(BigInteger.ONE)
                    .subtract(L.multiply(BigInteger.valueOf(quotient)));
            BigInteger maxRemainder = largest.min(L.subtract(BigInteger.ONE));
            for (BigInteger remainder : new BigInteger[]{
                    BigInteger.ZERO, BigInteger.ONE, maxRemainder}) {
                BigInteger value = L.multiply(BigInteger.valueOf(quotient)).add(remainder);
                if (value.compareTo(limit) >= 0) {
                    continue;
                }
                long[] reduced = new long[4];
                assertEquals(-1L, CtJubjubFrOps.fromUnsigned256Reduced(
                        reduced, 0, fixed32(value), 0, 256, new long[16], 0));
                assertEquals(value.mod(L), frValue(reduced),
                        "q=" + quotient + ", r=" + remainder);
            }
        }

        byte[] twoTo64 = fixed32(BigInteger.ONE.shiftLeft(64));
        assertEquals(0L, CtJubjubFrOps.fromUnsigned256Reduced(
                new long[4], 0, twoTo64, 0, 64, new long[16], 0));
        byte[] max64 = fixed32(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE));
        long[] reduced = new long[4];
        assertEquals(-1L, CtJubjubFrOps.fromUnsigned256Reduced(
                reduced, 0, max64, 0, 64, new long[16], 0));
        assertEquals(new BigInteger(1, max64).mod(L), frValue(reduced));
    }

    @Test
    @DisplayName("Montgomery constants have a pinned external digest")
    void constantDigestPin() throws Exception {
        // Digest of the canonical encodings of Fq(1), Fr(1), Fq(-1), Fr(-1). This catches
        // coordinated R/R2/modulus drift without exposing private kernel arrays.
        var digest = java.security.MessageDigest.getInstance("SHA-256");
        digest.update(fqBytes(fq(BigInteger.ONE)));
        digest.update(frBytes(fr(BigInteger.ONE)));
        digest.update(fqBytes(fq(P.subtract(BigInteger.ONE))));
        digest.update(frBytes(fr(L.subtract(BigInteger.ONE))));
        assertEquals("03edba695fb9c0d5080bd2dc9d888d5aa3146dc784b0efcaccba556620f78b3f",
                HexFormat.of().formatHex(digest.digest()));
    }

    @Test
    @DisplayName("Montgomery constants are independently derived from both moduli")
    void constantsAreIndependentlyDerived() throws Exception {
        assertMontgomeryConstants(CtJubjubFqOps.class, P);
        assertMontgomeryConstants(CtJubjubFrOps.class, L);
    }

    private static void assertFqBinary(BigInteger a, BigInteger b) {
        long[] aa = fq(a);
        long[] bb = fq(b);
        long[] out = new long[4];
        long[] work = new long[32];

        CtJubjubFqOps.add(out, 0, aa, 0, bb, 0);
        assertEquals(a.add(b).mod(P), fqValue(out));
        CtJubjubFqOps.sub(out, 0, aa, 0, bb, 0);
        assertEquals(a.subtract(b).mod(P), fqValue(out));
        CtJubjubFqOps.mul(out, 0, aa, 0, bb, 0, work, 0);
        assertEquals(a.multiply(b).mod(P), fqValue(out));
        CtJubjubFqOps.square(out, 0, aa, 0, work, 0);
        assertEquals(a.multiply(a).mod(P), fqValue(out));
        CtJubjubFqOps.neg(out, 0, aa, 0);
        assertEquals(a.negate().mod(P), fqValue(out));
    }

    private static void assertFrBinary(BigInteger a, BigInteger b) {
        long[] aa = fr(a);
        long[] bb = fr(b);
        long[] out = new long[4];
        long[] work = new long[32];

        CtJubjubFrOps.add(out, 0, aa, 0, bb, 0);
        assertEquals(a.add(b).mod(L), frValue(out));
        CtJubjubFrOps.sub(out, 0, aa, 0, bb, 0);
        assertEquals(a.subtract(b).mod(L), frValue(out));
        CtJubjubFrOps.mul(out, 0, aa, 0, bb, 0, work, 0);
        assertEquals(a.multiply(b).mod(L), frValue(out));
        CtJubjubFrOps.square(out, 0, aa, 0, work, 0);
        assertEquals(a.multiply(a).mod(L), frValue(out));
        CtJubjubFrOps.neg(out, 0, aa, 0);
        assertEquals(a.negate().mod(L), frValue(out));
    }

    private static void assertFqProperties(BigInteger a, BigInteger b, BigInteger c) {
        long[] aa = fq(a);
        long[] bb = fq(b);
        long[] cc = fq(c);
        long[] left = new long[4];
        long[] right = new long[4];
        long[] temporary = new long[4];
        long[] work = new long[32];

        CtJubjubFqOps.add(temporary, 0, bb, 0, cc, 0);
        CtJubjubFqOps.mul(left, 0, aa, 0, temporary, 0, work, 0);
        CtJubjubFqOps.mul(temporary, 0, aa, 0, bb, 0, work, 0);
        CtJubjubFqOps.mul(right, 0, aa, 0, cc, 0, work, 0);
        CtJubjubFqOps.add(right, 0, temporary, 0, right, 0);
        assertArrayEquals(left, right, "Fq distributivity");

        CtJubjubFqOps.add(left, 0, aa, 0, fq(BigInteger.ZERO), 0);
        assertArrayEquals(aa, left, "Fq additive identity");
        CtJubjubFqOps.mul(left, 0, aa, 0, fq(BigInteger.ONE), 0, work, 0);
        assertArrayEquals(aa, left, "Fq multiplicative identity");
    }

    private static void assertFrProperties(BigInteger a, BigInteger b, BigInteger c) {
        long[] aa = fr(a);
        long[] bb = fr(b);
        long[] cc = fr(c);
        long[] left = new long[4];
        long[] right = new long[4];
        long[] temporary = new long[4];
        long[] work = new long[32];

        CtJubjubFrOps.add(temporary, 0, bb, 0, cc, 0);
        CtJubjubFrOps.mul(left, 0, aa, 0, temporary, 0, work, 0);
        CtJubjubFrOps.mul(temporary, 0, aa, 0, bb, 0, work, 0);
        CtJubjubFrOps.mul(right, 0, aa, 0, cc, 0, work, 0);
        CtJubjubFrOps.add(right, 0, temporary, 0, right, 0);
        assertArrayEquals(left, right, "Fr distributivity");

        CtJubjubFrOps.add(left, 0, aa, 0, fr(BigInteger.ZERO), 0);
        assertArrayEquals(aa, left, "Fr additive identity");
        CtJubjubFrOps.mul(left, 0, aa, 0, fr(BigInteger.ONE), 0, work, 0);
        assertArrayEquals(aa, left, "Fr multiplicative identity");
    }

    private static void assertRawBorrowPropagation(long[] modulus) {
        BigInteger modulusValue = unsignedLimbs(modulus);
        BigInteger one = BigInteger.ONE;
        for (int resolvingLimb = 1; resolvingLimb < 4; resolvingLimb++) {
            BigInteger aValue = one.shiftLeft(64 * resolvingLimb);
            long[] a = littleEndianLimbs(aValue);
            long[] b = littleEndianLimbs(one);
            long[] out = new long[4];
            CtMontgomery256Ops.sub(out, 0, a, 0, b, 0, modulus);
            assertEquals(aValue.subtract(one), unsignedLimbs(out),
                    "borrow resolved in raw limb " + resolvingLimb);
        }

        long[] out = new long[4];
        CtMontgomery256Ops.sub(
                out, 0, new long[4], 0, littleEndianLimbs(one), 0, modulus);
        assertEquals(modulusValue.subtract(one), unsignedLimbs(out),
                "borrow propagated through all limbs and added the modulus");
    }

    private static long[] fq(BigInteger value) {
        long[] out = new long[4];
        assertEquals(-1L, CtJubjubFqOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[16], 0));
        return out;
    }

    private static long[] fr(BigInteger value) {
        long[] out = new long[4];
        assertEquals(-1L, CtJubjubFrOps.fromCanonicalBytes(
                out, 0, fixed32(value), 0, new long[16], 0));
        return out;
    }

    private static BigInteger fqValue(long[] value) {
        return new BigInteger(1, fqBytes(value));
    }

    private static BigInteger frValue(long[] value) {
        return new BigInteger(1, frBytes(value));
    }

    private static byte[] fqBytes(long[] value) {
        byte[] out = new byte[32];
        CtJubjubFqOps.toCanonicalBytes(out, 0, value, 0, new long[16], 0);
        return out;
    }

    private static byte[] frBytes(long[] value) {
        byte[] out = new byte[32];
        CtJubjubFrOps.toCanonicalBytes(out, 0, value, 0, new long[16], 0);
        return out;
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[32];
        int source = raw.length > 32 && raw[0] == 0 ? 1 : 0;
        int length = raw.length - source;
        System.arraycopy(raw, source, out, out.length - length, length);
        return out;
    }

    private static BigInteger randomBelow(BigInteger modulus) {
        BigInteger value;
        do {
            value = new BigInteger(modulus.bitLength(), RANDOM);
        } while (value.compareTo(modulus) >= 0);
        return value;
    }

    private static BigInteger randomNonZeroBelow(BigInteger modulus) {
        BigInteger value;
        do {
            value = randomBelow(modulus);
        } while (value.signum() == 0);
        return value;
    }

    private static void assertMontgomeryConstants(
            Class<?> kernel, BigInteger modulus) throws Exception {
        BigInteger radix = BigInteger.ONE.shiftLeft(256);
        BigInteger wordRadix = BigInteger.ONE.shiftLeft(64);
        assertEquals(modulus, unsignedLimbs(privateLongArray(kernel, "MODULUS")));
        assertEquals(radix.mod(modulus),
                unsignedLimbs(privateLongArray(kernel, "ONE")));
        assertEquals(radix.multiply(radix).mod(modulus),
                unsignedLimbs(privateLongArray(kernel, "R2")));

        Field inverseField = kernel.getDeclaredField("INVERSE");
        inverseField.setAccessible(true);
        long inverse = inverseField.getLong(null);
        BigInteger expectedInverse = wordRadix.subtract(
                modulus.mod(wordRadix).modInverse(wordRadix)).mod(wordRadix);
        assertEquals(expectedInverse, unsignedLong(inverse));
    }

    private static long[] privateLongArray(Class<?> owner, String name) throws Exception {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return ((long[]) field.get(null)).clone();
    }

    private static BigInteger unsignedLimbs(long[] limbs) {
        BigInteger value = BigInteger.ZERO;
        for (int i = limbs.length - 1; i >= 0; i--) {
            value = value.shiftLeft(64).add(unsignedLong(limbs[i]));
        }
        return value;
    }

    private static long[] littleEndianLimbs(BigInteger value) {
        long[] limbs = new long[4];
        BigInteger mask = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        for (int i = 0; i < limbs.length; i++) {
            limbs[i] = value.and(mask).longValue();
            value = value.shiftRight(64);
        }
        return limbs;
    }

    private static BigInteger unsignedLong(long value) {
        BigInteger result = BigInteger.valueOf(value);
        return result.signum() < 0 ? result.add(BigInteger.ONE.shiftLeft(64)) : result;
    }
}
