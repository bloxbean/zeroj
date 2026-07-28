package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * ADR-0039 fixed-limb kernel for the Jubjub base field
 * {@code p = 0x73eda753...00000001}. Values are four Montgomery-form limbs.
 */
final class CtJubjubFqOps {

    static final int LIMBS = 4;

    private static final long[] MODULUS = {
            0xffffffff00000001L, 0x53bda402fffe5bfeL,
            0x3339d80809a1d805L, 0x73eda753299d7d48L
    };
    private static final long INVERSE = 0xfffffffeffffffffL;
    private static final long[] ONE = {
            0x00000001fffffffeL, 0x5884b7fa00034802L,
            0x998c4fefecbc4ff5L, 0x1824b159acc5056fL
    };
    private static final long[] R2 = {
            0xc999e990f3f29c6dL, 0x2b6cedcb87925c23L,
            0x05d314967254398fL, 0x0748d9d99f59ff11L
    };
    private static final long[] P_MINUS_TWO = {
            0xfffffffeffffffffL, 0x53bda402fffe5bfeL,
            0x3339d80809a1d805L, 0x73eda753299d7d48L
    };

    private CtJubjubFqOps() {
    }

    static void zero(long[] out, int oo) {
        CtMontgomery256Ops.zero(out, oo);
    }

    static void one(long[] out, int oo) {
        CtMontgomery256Ops.copy(out, oo, ONE, 0);
    }

    static void copy(long[] out, int oo, long[] in, int io) {
        CtMontgomery256Ops.copy(out, oo, in, io);
    }

    static void add(long[] out, int oo, long[] a, int ao, long[] b, int bo) {
        CtMontgomery256Ops.add(out, oo, a, ao, b, bo, MODULUS);
    }

    static void sub(long[] out, int oo, long[] a, int ao, long[] b, int bo) {
        CtMontgomery256Ops.sub(out, oo, a, ao, b, bo, MODULUS);
    }

    static void neg(long[] out, int oo, long[] a, int ao) {
        CtMontgomery256Ops.neg(out, oo, a, ao, MODULUS);
    }

    static void mul(long[] out, int oo, long[] a, int ao, long[] b, int bo,
                    long[] work, int wo) {
        CtMontgomery256Ops.mul(out, oo, a, ao, b, bo, MODULUS, INVERSE, work, wo);
    }

    static void square(long[] out, int oo, long[] a, int ao, long[] work, int wo) {
        CtMontgomery256Ops.square(out, oo, a, ao, MODULUS, INVERSE, work, wo);
    }

    /**
     * Fixed-schedule exponentiation by {@code p-2}. For zero input this deliberately returns
     * zero; callers requiring a mathematical inverse must establish nonzero input separately
     * without shortening the schedule.
     */
    static void invert(long[] out, int oo, long[] a, int ao, long[] work, int wo) {
        CtMontgomery256Ops.pow(out, oo, a, ao, P_MINUS_TWO, ONE,
                MODULUS, INVERSE, work, wo);
    }

    static long fromCanonicalBytes(long[] out, int oo, byte[] encoded, int eo,
                                   long[] work, int wo) {
        return CtMontgomery256Ops.fromCanonicalBytes(
                out, oo, encoded, eo, MODULUS, R2, INVERSE, work, wo);
    }

    static void fromUnsigned128(long[] out, int oo, byte[] encoded, int eo,
                                long[] work, int wo) {
        CtMontgomery256Ops.fromUnsigned128(
                out, oo, encoded, eo, MODULUS, R2, INVERSE, work, wo);
    }

    static void fromNormal(long[] out, int oo, long[] normal, int no,
                           long[] work, int wo) {
        CtMontgomery256Ops.fromNormal(
                out, oo, normal, no, R2, MODULUS, INVERSE, work, wo);
    }

    static void toNormal(long[] out, int oo, long[] value, int vo,
                         long[] work, int wo) {
        CtMontgomery256Ops.toNormal(out, oo, value, vo, MODULUS, INVERSE, work, wo);
    }

    static void toCanonicalBytes(byte[] out, int oo, long[] value, int vo,
                                 long[] work, int wo) {
        CtMontgomery256Ops.toCanonicalBytes(
                out, oo, value, vo, MODULUS, INVERSE, work, wo);
    }

    static long zeroMask(long[] value, int offset) {
        return CtMontgomery256Ops.zeroMask(value, offset);
    }

    static long equalMask(long[] a, int ao, long[] b, int bo) {
        return CtMontgomery256Ops.equalMask(a, ao, b, bo);
    }

    static void select(long[] out, int oo,
                       long[] whenSet, int so, long[] whenClear, int co,
                       long mask) {
        CtMontgomery256Ops.select(out, oo, whenSet, so, whenClear, co, mask);
    }
}
