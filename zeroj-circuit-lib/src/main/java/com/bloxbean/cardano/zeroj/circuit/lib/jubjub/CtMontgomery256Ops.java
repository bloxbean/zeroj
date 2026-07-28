package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.util.Arrays;

/**
 * Internal allocation-free Montgomery arithmetic shared by the two ADR-0039 four-limb
 * kernels. This class contains no modulus of its own and is not a general public integer API.
 *
 * <p>All values are four little-endian 64-bit limbs. Carry, borrow, conditional reduction,
 * equality, and selection are expressed as arithmetic masks. Loop bounds and array offsets are
 * public and fixed. Callers provide a disjoint work region; output may alias either input.
 */
final class CtMontgomery256Ops {

    static final int LIMBS = 4;
    private static final long[] NORMAL_ZERO = {0L, 0L, 0L, 0L};
    private static final long[] NORMAL_ONE = {1L, 0L, 0L, 0L};

    private CtMontgomery256Ops() {
    }

    static void copy(long[] out, int oo, long[] in, int io) {
        out[oo] = in[io];
        out[oo + 1] = in[io + 1];
        out[oo + 2] = in[io + 2];
        out[oo + 3] = in[io + 3];
    }

    static void zero(long[] out, int oo) {
        out[oo] = 0L;
        out[oo + 1] = 0L;
        out[oo + 2] = 0L;
        out[oo + 3] = 0L;
    }

    static void select(long[] out, int oo,
                       long[] whenSet, int so,
                       long[] whenClear, int co,
                       long mask) {
        long inverse = ~mask;
        out[oo] = (whenSet[so] & mask) | (whenClear[co] & inverse);
        out[oo + 1] = (whenSet[so + 1] & mask) | (whenClear[co + 1] & inverse);
        out[oo + 2] = (whenSet[so + 2] & mask) | (whenClear[co + 2] & inverse);
        out[oo + 3] = (whenSet[so + 3] & mask) | (whenClear[co + 3] & inverse);
    }

    /** Returns all ones iff the element is zero, otherwise zero. */
    static long zeroMask(long[] value, int offset) {
        long combined = value[offset] | value[offset + 1] | value[offset + 2]
                | value[offset + 3];
        return ((combined | -combined) >>> 63) - 1L;
    }

    /** Returns all ones iff the two elements are equal, otherwise zero. */
    static long equalMask(long[] a, int ao, long[] b, int bo) {
        long different = (a[ao] ^ b[bo])
                | (a[ao + 1] ^ b[bo + 1])
                | (a[ao + 2] ^ b[bo + 2])
                | (a[ao + 3] ^ b[bo + 3]);
        return ((different | -different) >>> 63) - 1L;
    }

    /** Returns all ones iff the unsigned four-limb value is strictly below the modulus. */
    static long lessThanModMask(long[] value, int vo, long[] modulus) {
        long borrow;
        long d0 = value[vo] - modulus[0];
        borrow = subBorrow(value[vo], modulus[0], d0);

        long t = value[vo + 1] - modulus[1];
        long b1 = subBorrow(value[vo + 1], modulus[1], t);
        long d1 = t - borrow;
        long b2 = subBorrow(t, borrow, d1);
        borrow = b1 | b2;

        t = value[vo + 2] - modulus[2];
        b1 = subBorrow(value[vo + 2], modulus[2], t);
        long d2 = t - borrow;
        b2 = subBorrow(t, borrow, d2);
        borrow = b1 | b2;

        t = value[vo + 3] - modulus[3];
        b1 = subBorrow(value[vo + 3], modulus[3], t);
        long d3 = t - borrow;
        b2 = subBorrow(t, borrow, d3);
        borrow = b1 | b2;

        // Keep the locals live as a guard against accidentally changing this into a partial
        // comparison during maintenance.
        long ignored = d0 ^ d1 ^ d2 ^ d3;
        return -borrow | (ignored & 0L);
    }

    static void add(long[] out, int oo,
                    long[] a, int ao, long[] b, int bo,
                    long[] modulus) {
        long s0 = a[ao] + b[bo];
        long carry = addCarry(a[ao], b[bo], s0);

        long t = a[ao + 1] + b[bo + 1];
        long c1 = addCarry(a[ao + 1], b[bo + 1], t);
        long s1 = t + carry;
        long c2 = addCarry(t, carry, s1);
        carry = c1 | c2;

        t = a[ao + 2] + b[bo + 2];
        c1 = addCarry(a[ao + 2], b[bo + 2], t);
        long s2 = t + carry;
        c2 = addCarry(t, carry, s2);
        carry = c1 | c2;

        t = a[ao + 3] + b[bo + 3];
        c1 = addCarry(a[ao + 3], b[bo + 3], t);
        long s3 = t + carry;
        c2 = addCarry(t, carry, s3);
        carry = c1 | c2;

        subtractModAndSelect(out, oo, s0, s1, s2, s3, carry, modulus);
    }

    static void sub(long[] out, int oo,
                    long[] a, int ao, long[] b, int bo,
                    long[] modulus) {
        long d0 = a[ao] - b[bo];
        long borrow = subBorrow(a[ao], b[bo], d0);

        long t = a[ao + 1] - b[bo + 1];
        long b1 = subBorrow(a[ao + 1], b[bo + 1], t);
        long d1 = t - borrow;
        long b2 = subBorrow(t, borrow, d1);
        borrow = b1 | b2;

        t = a[ao + 2] - b[bo + 2];
        b1 = subBorrow(a[ao + 2], b[bo + 2], t);
        long d2 = t - borrow;
        b2 = subBorrow(t, borrow, d2);
        borrow = b1 | b2;

        t = a[ao + 3] - b[bo + 3];
        b1 = subBorrow(a[ao + 3], b[bo + 3], t);
        long d3 = t - borrow;
        b2 = subBorrow(t, borrow, d3);
        borrow = b1 | b2;

        long mask = -borrow;
        long add0 = modulus[0] & mask;
        long s0 = d0 + add0;
        long carry = addCarry(d0, add0, s0);

        long add1 = modulus[1] & mask;
        t = d1 + add1;
        long c1 = addCarry(d1, add1, t);
        long s1 = t + carry;
        long c2 = addCarry(t, carry, s1);
        carry = c1 | c2;

        long add2 = modulus[2] & mask;
        t = d2 + add2;
        c1 = addCarry(d2, add2, t);
        long s2 = t + carry;
        c2 = addCarry(t, carry, s2);
        carry = c1 | c2;

        long add3 = modulus[3] & mask;
        t = d3 + add3;
        long s3 = t + carry;

        out[oo] = s0;
        out[oo + 1] = s1;
        out[oo + 2] = s2;
        out[oo + 3] = s3;
    }

    static void neg(long[] out, int oo, long[] a, int ao, long[] modulus) {
        sub(out, oo, NORMAL_ZERO, 0, a, ao, modulus);
    }

    /**
     * Four-limb CIOS Montgomery multiplication. {@code work[wo]} is a one-limb carry slot.
     *
     * <p>The shared helper is intentionally limited to the two moduli in ADR-0039, both of
     * which are below {@code 2^255}. For canonical operands, the top-word merge cannot
     * overflow: each multiply carry is bounded by the corresponding top modulus limb (plus
     * the correlated carry bit), and twice either supported top limb is below {@code 2^64}.
     * The CIOS result is below twice the modulus, so one final mask-selected subtraction is
     * sufficient. Differential tests independently derive both Montgomery domains and stress
     * every 64-bit limb boundary; this is not a general arbitrary-modulus routine.
     */
    static void mul(long[] out, int oo,
                    long[] a, int ao, long[] b, int bo,
                    long[] modulus, long inverse,
                    long[] work, int wo) {
        long a0 = a[ao];
        long a1 = a[ao + 1];
        long a2 = a[ao + 2];
        long a3 = a[ao + 3];
        long b0 = b[bo];
        long b1 = b[bo + 1];
        long b2 = b[bo + 2];
        long b3 = b[bo + 3];
        long t0 = 0L;
        long t1 = 0L;
        long t2 = 0L;
        long t3 = 0L;

        for (int i = 0; i < LIMBS; i++) {
            long ai = switch (i) {
                case 0 -> a0;
                case 1 -> a1;
                case 2 -> a2;
                default -> a3;
            };
            work[wo] = 0L;
            t0 = mac(t0, ai, b0, work, wo);
            t1 = mac(t1, ai, b1, work, wo);
            t2 = mac(t2, ai, b2, work, wo);
            t3 = mac(t3, ai, b3, work, wo);
            long t4 = work[wo];

            long m = t0 * inverse;
            work[wo] = 0L;
            mac(t0, m, modulus[0], work, wo);
            t0 = mac(t1, m, modulus[1], work, wo);
            t1 = mac(t2, m, modulus[2], work, wo);
            t2 = mac(t3, m, modulus[3], work, wo);
            t3 = work[wo] + t4;
        }

        subtractModAndSelect(out, oo, t0, t1, t2, t3, 0L, modulus);
    }

    static void square(long[] out, int oo, long[] a, int ao,
                       long[] modulus, long inverse,
                       long[] work, int wo) {
        mul(out, oo, a, ao, a, ao, modulus, inverse, work, wo);
    }

    /** Performs one mask-selected subtraction of {@code modulus} from a normal-form value. */
    static void conditionalSubtract(long[] value, int vo, long[] modulus) {
        long s0 = value[vo];
        long s1 = value[vo + 1];
        long s2 = value[vo + 2];
        long s3 = value[vo + 3];
        subtractModAndSelect(value, vo, s0, s1, s2, s3, 0L, modulus);
    }

    /** Converts a canonical normal-form value to Montgomery form. Work uses one limb. */
    static void fromNormal(long[] out, int oo, long[] normal, int no,
                           long[] r2, long[] modulus, long inverse,
                           long[] work, int wo) {
        mul(out, oo, normal, no, r2, 0, modulus, inverse, work, wo);
    }

    /**
     * Fixed 256-bit square-and-multiply schedule for a public, pinned exponent.
     * Work uses 13 limbs beginning at {@code wo}.
     */
    static void pow(long[] out, int oo, long[] a, int ao,
                    long[] exponent, long[] one,
                    long[] modulus, long inverse,
                    long[] work, int wo) {
        int acc = wo;
        int squared = wo + 4;
        int product = wo + 8;
        int carry = wo + 12;
        copy(work, acc, one, 0);
        for (int bit = 255; bit >= 0; bit--) {
            square(work, squared, work, acc, modulus, inverse, work, carry);
            mul(work, product, work, squared, a, ao, modulus, inverse, work, carry);
            long bitValue = (exponent[bit >>> 6] >>> (bit & 63)) & 1L;
            select(work, acc, work, product, work, squared, -bitValue);
        }
        copy(out, oo, work, acc);
    }

    /**
     * Parses a canonical unsigned 32-byte big-endian value and converts it to Montgomery form.
     * Returns all ones for a canonical input, otherwise zero. Work uses five limbs.
     */
    static long fromCanonicalBytes(long[] out, int oo, byte[] encoded, int eo,
                                   long[] modulus, long[] r2, long inverse,
                                   long[] work, int wo) {
        readBigEndian32(work, wo, encoded, eo);
        long canonical = lessThanModMask(work, wo, modulus);
        mul(out, oo, work, wo, r2, 0, modulus, inverse, work, wo + 4);
        return canonical;
    }

    /**
     * Imports exactly 16 big-endian bytes as a canonical field element. Work uses five limbs.
     */
    static void fromUnsigned128(long[] out, int oo, byte[] encoded, int eo,
                                long[] modulus, long[] r2, long inverse,
                                long[] work, int wo) {
        work[wo] = readLongBigEndian(encoded, eo + 8);
        work[wo + 1] = readLongBigEndian(encoded, eo);
        work[wo + 2] = 0L;
        work[wo + 3] = 0L;
        mul(out, oo, work, wo, r2, 0, modulus, inverse, work, wo + 4);
    }

    /** Converts a Montgomery element to four canonical normal limbs. Work uses one limb. */
    static void toNormal(long[] out, int oo, long[] value, int vo,
                         long[] modulus, long inverse,
                         long[] work, int wo) {
        mul(out, oo, value, vo, NORMAL_ONE, 0, modulus, inverse, work, wo);
    }

    /** Converts a Montgomery element to canonical 32-byte big-endian form. Work uses 5 limbs. */
    static void toCanonicalBytes(byte[] out, int oo, long[] value, int vo,
                                 long[] modulus, long inverse,
                                 long[] work, int wo) {
        toNormal(work, wo, value, vo, modulus, inverse, work, wo + 4);
        for (int limb = 0; limb < LIMBS; limb++) {
            writeLongBigEndian(out, oo + 24 - limb * 8, work[wo + limb]);
        }
    }

    static void wipe(long[] values) {
        Arrays.fill(values, 0L);
    }

    static void readBigEndian32(long[] out, int oo, byte[] encoded, int eo) {
        out[oo] = readLongBigEndian(encoded, eo + 24);
        out[oo + 1] = readLongBigEndian(encoded, eo + 16);
        out[oo + 2] = readLongBigEndian(encoded, eo + 8);
        out[oo + 3] = readLongBigEndian(encoded, eo);
    }

    private static long readLongBigEndian(byte[] encoded, int offset) {
        long value = 0L;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (encoded[offset + i] & 0xffL);
        }
        return value;
    }

    private static void writeLongBigEndian(byte[] out, int offset, long value) {
        for (int i = 7; i >= 0; i--) {
            out[offset + i] = (byte) value;
            value >>>= 8;
        }
    }

    private static long mac(long accumulator, long a, long b, long[] work, int wo) {
        // As an unsigned 128-bit value:
        //   a*b + accumulator + incomingCarry
        // <= (B-1)^2 + 2(B-1) = B^2-1, B=2^64.
        // Therefore high + the two correlated carry bits cannot overflow its output limb.
        long low = a * b;
        long high = Math.unsignedMultiplyHigh(a, b);
        long sum = low + accumulator;
        long carry1 = addCarry(low, accumulator, sum);
        long result = sum + work[wo];
        long carry2 = addCarry(sum, work[wo], result);
        work[wo] = high + carry1 + carry2;
        return result;
    }

    private static void subtractModAndSelect(long[] out, int oo,
                                             long s0, long s1, long s2, long s3,
                                             long carry, long[] modulus) {
        long d0 = s0 - modulus[0];
        long borrow = subBorrow(s0, modulus[0], d0);

        long t = s1 - modulus[1];
        long b1 = subBorrow(s1, modulus[1], t);
        long d1 = t - borrow;
        long b2 = subBorrow(t, borrow, d1);
        borrow = b1 | b2;

        t = s2 - modulus[2];
        b1 = subBorrow(s2, modulus[2], t);
        long d2 = t - borrow;
        b2 = subBorrow(t, borrow, d2);
        borrow = b1 | b2;

        t = s3 - modulus[3];
        b1 = subBorrow(s3, modulus[3], t);
        long d3 = t - borrow;
        b2 = subBorrow(t, borrow, d3);
        borrow = b1 | b2;

        long selectDifference = carry | (borrow ^ 1L);
        long mask = -selectDifference;
        long inverseMask = ~mask;
        out[oo] = (d0 & mask) | (s0 & inverseMask);
        out[oo + 1] = (d1 & mask) | (s1 & inverseMask);
        out[oo + 2] = (d2 & mask) | (s2 & inverseMask);
        out[oo + 3] = (d3 & mask) | (s3 & inverseMask);
    }

    private static long addCarry(long a, long b, long sum) {
        return ((a & b) | ((a | b) & ~sum)) >>> 63;
    }

    private static long subBorrow(long a, long b, long difference) {
        return ((~a & b) | (~(a ^ b) & difference)) >>> 63;
    }
}
