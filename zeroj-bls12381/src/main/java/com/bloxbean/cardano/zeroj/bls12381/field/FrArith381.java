package com.bloxbean.cardano.zeroj.bls12381.field;

/**
 * Allocation-free BLS12-381 scalar-field (Fr) arithmetic over flat {@code long[]} storage
 * (ADR-0029 M2c) — the 4-limb analog of {@link FpArith381}, for the allocation-lean FFT.
 *
 * <p>An element is 4 consecutive Montgomery-form limbs at an offset. Operations read inputs into
 * locals and write the result at the end, so the output may alias an input. Byte-for-byte port of
 * {@link MontFr381}'s CIOS multiply + add/sub; {@link MontFr381} stays the bit-identical oracle
 * (see {@code FrArith381Test}).</p>
 */
public final class FrArith381 {

    private FrArith381() {}

    /** Limbs per Fr element. */
    public static final int LIMBS = 4;

    private static final long MOD0 = MontFr381.MOD0, MOD1 = MontFr381.MOD1, MOD2 = MontFr381.MOD2, MOD3 = MontFr381.MOD3;
    private static final long INV = MontFr381.INV;

    public static void copy(long[] o, int oo, long[] a, int ao) {
        o[oo] = a[ao]; o[oo + 1] = a[ao + 1]; o[oo + 2] = a[ao + 2]; o[oo + 3] = a[ao + 3];
    }

    public static boolean isZero(long[] a, int ao) {
        return a[ao] == 0 && a[ao + 1] == 0 && a[ao + 2] == 0 && a[ao + 3] == 0;
    }

    /** {@code o = a + b} (mod r). Output may alias an input. */
    public static void add(long[] o, int oo, long[] a, int ao, long[] b, int bo) {
        long a0 = a[ao], a1 = a[ao + 1], a2 = a[ao + 2], a3 = a[ao + 3];
        long b0 = b[bo], b1 = b[bo + 1], b2 = b[bo + 2], b3 = b[bo + 3];

        long s0 = a0 + b0;
        long c = Long.compareUnsigned(s0, a0) < 0 ? 1 : 0;
        long s1 = a1 + b1 + c;
        c = (c != 0) ? (Long.compareUnsigned(s1, a1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, a1) < 0 ? 1 : 0);
        long s2 = a2 + b2 + c;
        c = (c != 0) ? (Long.compareUnsigned(s2, a2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, a2) < 0 ? 1 : 0);
        long s3 = a3 + b3 + c;
        c = (c != 0) ? (Long.compareUnsigned(s3, a3) <= 0 ? 1 : 0) : (Long.compareUnsigned(s3, a3) < 0 ? 1 : 0);

        subModTo(o, oo, s0, s1, s2, s3, c);
    }

    /** {@code o = a - b} (mod r). Output may alias an input. */
    public static void sub(long[] o, int oo, long[] a, int ao, long[] b, int bo) {
        long a0 = a[ao], a1 = a[ao + 1], a2 = a[ao + 2], a3 = a[ao + 3];
        long b0 = b[bo], b1 = b[bo + 1], b2 = b[bo + 2], b3 = b[bo + 3];

        long d0 = a0 - b0;
        long borrow = Long.compareUnsigned(a0, b0) < 0 ? 1 : 0;
        long d1 = a1 - b1 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a1, b1) <= 0 ? 1 : 0) : (Long.compareUnsigned(a1, b1) < 0 ? 1 : 0);
        long d2 = a2 - b2 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a2, b2) <= 0 ? 1 : 0) : (Long.compareUnsigned(a2, b2) < 0 ? 1 : 0);
        long d3 = a3 - b3 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a3, b3) <= 0 ? 1 : 0) : (Long.compareUnsigned(a3, b3) < 0 ? 1 : 0);

        if (borrow != 0) {
            long c;
            d0 = d0 + MOD0; c = Long.compareUnsigned(d0, MOD0) < 0 ? 1 : 0;
            d1 = d1 + MOD1 + c; c = (c != 0) ? (Long.compareUnsigned(d1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(d1, MOD1) < 0 ? 1 : 0);
            d2 = d2 + MOD2 + c; c = (c != 0) ? (Long.compareUnsigned(d2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(d2, MOD2) < 0 ? 1 : 0);
            d3 = d3 + MOD3 + c;
        }
        o[oo] = d0; o[oo + 1] = d1; o[oo + 2] = d2; o[oo + 3] = d3;
    }

    /** {@code o = a * b} (Montgomery, CIOS 4-limb). Output may alias either input. */
    public static void mul(long[] o, int oo, long[] a, int ao, long[] b, int bo) {
        long a0 = a[ao], a1 = a[ao + 1], a2 = a[ao + 2], a3 = a[ao + 3];
        long b0 = b[bo], b1 = b[bo + 1], b2 = b[bo + 2], b3 = b[bo + 3];

        long[] c = {0};
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4, m;
        for (int i = 0; i < 4; i++) {
            long ai = switch (i) { case 0 -> a0; case 1 -> a1; case 2 -> a2; default -> a3; };
            c[0] = 0;
            t0 = mac(t0, ai, b0, c); t1 = mac(t1, ai, b1, c); t2 = mac(t2, ai, b2, c); t3 = mac(t3, ai, b3, c);
            t4 = c[0];
            m = t0 * INV;
            c[0] = 0;
            mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c);
            t3 = c[0] + t4;
        }
        subModTo(o, oo, t0, t1, t2, t3, 0);
    }

    public static void sqr(long[] o, int oo, long[] a, int ao) { mul(o, oo, a, ao, a, ao); }

    private static long mac(long acc, long a, long b, long[] state) {
        long lo = a * b;
        long hi = Math.unsignedMultiplyHigh(a, b);
        long sum = lo + acc;
        long carry1 = Long.compareUnsigned(sum, lo) < 0 ? 1 : 0;
        long result = sum + state[0];
        long carry2 = Long.compareUnsigned(result, sum) < 0 ? 1 : 0;
        state[0] = hi + carry1 + carry2;
        return result;
    }

    private static void subModTo(long[] o, int oo, long s0, long s1, long s2, long s3, long carry) {
        if (carry != 0 || geqMod(s0, s1, s2, s3)) {
            long borrow;
            long d0 = s0 - MOD0; borrow = Long.compareUnsigned(s0, MOD0) < 0 ? 1 : 0;
            long d1 = s1 - MOD1 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, MOD1) < 0 ? 1 : 0);
            long d2 = s2 - MOD2 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, MOD2) < 0 ? 1 : 0);
            long d3 = s3 - MOD3 - borrow;
            o[oo] = d0; o[oo + 1] = d1; o[oo + 2] = d2; o[oo + 3] = d3;
        } else {
            o[oo] = s0; o[oo + 1] = s1; o[oo + 2] = s2; o[oo + 3] = s3;
        }
    }

    private static boolean geqMod(long l0, long l1, long l2, long l3) {
        if (Long.compareUnsigned(l3, MOD3) != 0) return Long.compareUnsigned(l3, MOD3) > 0;
        if (Long.compareUnsigned(l2, MOD2) != 0) return Long.compareUnsigned(l2, MOD2) > 0;
        if (Long.compareUnsigned(l1, MOD1) != 0) return Long.compareUnsigned(l1, MOD1) > 0;
        return Long.compareUnsigned(l0, MOD0) >= 0;
    }
}
