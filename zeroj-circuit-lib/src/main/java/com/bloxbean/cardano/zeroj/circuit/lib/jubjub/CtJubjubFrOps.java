package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * ADR-0039 fixed-limb kernel for the Jubjub prime-order scalar field
 * {@code l = 0x0e7db4ea...d6f72cb7}. Values are four Montgomery-form limbs.
 */
final class CtJubjubFrOps {

    static final int LIMBS = 4;

    private static final long[] MODULUS = {
            0xd0970e5ed6f72cb7L, 0xa6682093ccc81082L,
            0x06673b0101343b00L, 0x0e7db4ea6533afa9L
    };
    private static final long[] MODULUS_MINUS_ONE = {
            0xd0970e5ed6f72cb6L, 0xa6682093ccc81082L,
            0x06673b0101343b00L, 0x0e7db4ea6533afa9L
    };
    private static final long INVERSE = 0x1ba3a358ef788ef9L;
    private static final long[] ONE = {
            0x25f80bb3b99607d9L, 0xf315d62f66b6e750L,
            0x932514eeeb8814f4L, 0x09a6fc6f479155c6L
    };
    private static final long[] R2 = {
            0x67719aa495e57731L, 0x51b0cef09ce3fc26L,
            0x69dab7fac026e9a5L, 0x04f6547b8d127688L
    };
    private static final long[] L_MINUS_TWO = {
            0xd0970e5ed6f72cb5L, 0xa6682093ccc81082L,
            0x06673b0101343b00L, 0x0e7db4ea6533afa9L
    };

    private CtJubjubFrOps() {
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
     * Fixed-schedule exponentiation by {@code l-2}. For zero input this deliberately returns
     * zero; callers requiring a mathematical inverse must establish nonzero input separately
     * without shortening the schedule.
     */
    static void invert(long[] out, int oo, long[] a, int ao, long[] work, int wo) {
        CtMontgomery256Ops.pow(out, oo, a, ao, L_MINUS_TWO, ONE,
                MODULUS, INVERSE, work, wo);
    }

    static long fromCanonicalBytes(long[] out, int oo, byte[] encoded, int eo,
                                   long[] work, int wo) {
        return CtMontgomery256Ops.fromCanonicalBytes(
                out, oo, encoded, eo, MODULUS, R2, INVERSE, work, wo);
    }

    /**
     * Reduces an unsigned 256-bit big-endian value modulo {@code l}. The declared width is
     * public and must be in {@code [1,256]}; the method returns all ones iff bits above that
     * width are zero. Reduction always performs exactly 17 candidate subtractions, sufficient
     * because {@code floor((2^256-1)/l) = 17}.
     *
     * <p>The current CIOS conversion also happens to reduce this wider first operand when its
     * second operand is canonical {@code R^2}. These rounds are nevertheless intentional:
     * they establish {@code fromNormal}'s documented canonical-input precondition and pin the
     * reviewed fixed reduction schedule rather than depending on a broader incidental CIOS
     * input bound.
     */
    static long fromUnsigned256Reduced(long[] out, int oo,
                                       byte[] encoded, int eo, int declaredBits,
                                       long[] work, int wo) {
        if (declaredBits < 1 || declaredBits > 256) {
            throw new IllegalArgumentException("declaredBits must be in [1,256]");
        }
        long invalid = 0L;
        int unused = 256 - declaredBits;
        int fullUnusedBytes = unused >>> 3;
        int partialUnusedBits = unused & 7;
        for (int i = 0; i < 32; i++) {
            long fullMask = i < fullUnusedBytes ? 0xffL : 0L;
            long partialMask = i == fullUnusedBytes && partialUnusedBits != 0
                    ? (0xffL << (8 - partialUnusedBits)) & 0xffL
                    : 0L;
            invalid |= (encoded[eo + i] & 0xffL) & (fullMask | partialMask);
        }
        CtMontgomery256Ops.readBigEndian32(work, wo, encoded, eo);
        for (int i = 0; i < 17; i++) {
            CtMontgomery256Ops.conditionalSubtract(work, wo, MODULUS);
        }
        fromNormal(out, oo, work, wo, work, wo + 4);
        return ((invalid | -invalid) >>> 63) - 1L;
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

    /**
     * Reduces a canonical Jubjub-base-field value modulo {@code l} with exactly eight
     * mask-selected subtraction rounds. As above, the rounds deliberately establish the
     * canonical input required by {@code fromNormal}; they are not removed merely because
     * the current CIOS implementation also reduces this particular wider operand.
     */
    static void reduceFromFq(long[] out, int oo, long[] fq, int fo,
                             long[] work, int wo) {
        CtJubjubFqOps.toNormal(work, wo, fq, fo, work, wo + 4);
        for (int i = 0; i < 8; i++) {
            CtMontgomery256Ops.conditionalSubtract(work, wo, MODULUS);
        }
        fromNormal(out, oo, work, wo, work, wo + 4);
    }

    /**
     * Maps a canonical base-field value into {@code [1,l)} as
     * {@code (x mod (l-1)) + 1}, using exactly eight subtraction rounds.
     */
    static void mapFromFqNonZero(long[] out, int oo, long[] fq, int fo,
                                 long[] work, int wo) {
        CtJubjubFqOps.toNormal(work, wo, fq, fo, work, wo + 4);
        for (int i = 0; i < 8; i++) {
            CtMontgomery256Ops.conditionalSubtract(work, wo, MODULUS_MINUS_ONE);
        }

        long old = work[wo];
        long sum = old + 1L;
        long carry = ((old & 1L) | ((old | 1L) & ~sum)) >>> 63;
        work[wo] = sum;
        for (int i = 1; i < LIMBS; i++) {
            old = work[wo + i];
            sum = old + carry;
            long nextCarry = ((old & carry) | ((old | carry) & ~sum)) >>> 63;
            work[wo + i] = sum;
            carry = nextCarry;
        }
        fromNormal(out, oo, work, wo, work, wo + 4);
    }
}
