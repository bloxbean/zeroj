package com.bloxbean.cardano.zeroj.bls12381.field;

/**
 * Allocation-free BLS12-381 Fp arithmetic over flat {@code long[]} storage (ADR-0029 M1a).
 *
 * <p>An element is 6 consecutive Montgomery-form limbs (little-endian, {@code l0} least significant)
 * at an offset into a {@code long[]}. Every operation reads its inputs into locals first and writes
 * the 6 result limbs at the end, so <b>the output may alias either input</b> (e.g. squaring, or
 * {@code mul(x, x, y)}). The math is a byte-for-byte port of {@link MontFp381}'s CIOS multiply and
 * add/sub — {@link MontFp381} stays the frozen bit-identical oracle (see {@code FpArith381Test}).</p>
 *
 * <p>Purpose: let the MSM / point hot loop and the packed proving key operate on flat arrays with
 * reused scratch buffers, eliminating the per-op {@link MontFp381} object allocation that is the
 * prover's memory ceiling (ADR-0029 M0 finding).</p>
 */
public final class FpArith381 {

    private FpArith381() {}

    /** Limbs per Fp element. */
    public static final int LIMBS = 6;

    // Reuse MontFp381's Montgomery constants (same package).
    private static final long MOD0 = MontFp381.MOD0, MOD1 = MontFp381.MOD1, MOD2 = MontFp381.MOD2,
            MOD3 = MontFp381.MOD3, MOD4 = MontFp381.MOD4, MOD5 = MontFp381.MOD5;
    private static final long INV = MontFp381.INV;

    /** Copy 6 limbs {@code a[ao..]} → {@code o[oo..]}. */
    public static void copy(long[] o, int oo, long[] a, int ao) {
        o[oo] = a[ao]; o[oo + 1] = a[ao + 1]; o[oo + 2] = a[ao + 2];
        o[oo + 3] = a[ao + 3]; o[oo + 4] = a[ao + 4]; o[oo + 5] = a[ao + 5];
    }

    /** True if the element at {@code a[ao..]} is zero. */
    public static boolean isZero(long[] a, int ao) {
        return a[ao] == 0 && a[ao + 1] == 0 && a[ao + 2] == 0
                && a[ao + 3] == 0 && a[ao + 4] == 0 && a[ao + 5] == 0;
    }

    /** True if the two elements are limb-equal (both must be canonical Montgomery residues). */
    public static boolean eq(long[] a, int ao, long[] b, int bo) {
        return a[ao] == b[bo] && a[ao + 1] == b[bo + 1] && a[ao + 2] == b[bo + 2]
                && a[ao + 3] == b[bo + 3] && a[ao + 4] == b[bo + 4] && a[ao + 5] == b[bo + 5];
    }

    // ------------------------------------------------------------------
    // add / sub
    // ------------------------------------------------------------------

    /** {@code o = a + b} (mod p). Port of {@link MontFp381#add}. Output may alias an input. */
    public static void add(long[] o, int oo, long[] a, int ao, long[] b, int bo) {
        long a0 = a[ao], a1 = a[ao + 1], a2 = a[ao + 2], a3 = a[ao + 3], a4 = a[ao + 4], a5 = a[ao + 5];
        long b0 = b[bo], b1 = b[bo + 1], b2 = b[bo + 2], b3 = b[bo + 3], b4 = b[bo + 4], b5 = b[bo + 5];

        long s0 = a0 + b0;
        long c = Long.compareUnsigned(s0, a0) < 0 ? 1 : 0;
        long s1 = a1 + b1 + c;
        c = (c != 0) ? (Long.compareUnsigned(s1, a1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, a1) < 0 ? 1 : 0);
        long s2 = a2 + b2 + c;
        c = (c != 0) ? (Long.compareUnsigned(s2, a2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, a2) < 0 ? 1 : 0);
        long s3 = a3 + b3 + c;
        c = (c != 0) ? (Long.compareUnsigned(s3, a3) <= 0 ? 1 : 0) : (Long.compareUnsigned(s3, a3) < 0 ? 1 : 0);
        long s4 = a4 + b4 + c;
        c = (c != 0) ? (Long.compareUnsigned(s4, a4) <= 0 ? 1 : 0) : (Long.compareUnsigned(s4, a4) < 0 ? 1 : 0);
        long s5 = a5 + b5 + c;
        c = (c != 0) ? (Long.compareUnsigned(s5, a5) <= 0 ? 1 : 0) : (Long.compareUnsigned(s5, a5) < 0 ? 1 : 0);

        subModTo(o, oo, s0, s1, s2, s3, s4, s5, c);
    }

    /** {@code o = a - b} (mod p). Port of {@link MontFp381#sub}. Output may alias an input. */
    public static void sub(long[] o, int oo, long[] a, int ao, long[] b, int bo) {
        long a0 = a[ao], a1 = a[ao + 1], a2 = a[ao + 2], a3 = a[ao + 3], a4 = a[ao + 4], a5 = a[ao + 5];
        long b0 = b[bo], b1 = b[bo + 1], b2 = b[bo + 2], b3 = b[bo + 3], b4 = b[bo + 4], b5 = b[bo + 5];

        long d0 = a0 - b0;
        long borrow = Long.compareUnsigned(a0, b0) < 0 ? 1 : 0;
        long d1 = a1 - b1 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a1, b1) <= 0 ? 1 : 0) : (Long.compareUnsigned(a1, b1) < 0 ? 1 : 0);
        long d2 = a2 - b2 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a2, b2) <= 0 ? 1 : 0) : (Long.compareUnsigned(a2, b2) < 0 ? 1 : 0);
        long d3 = a3 - b3 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a3, b3) <= 0 ? 1 : 0) : (Long.compareUnsigned(a3, b3) < 0 ? 1 : 0);
        long d4 = a4 - b4 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a4, b4) <= 0 ? 1 : 0) : (Long.compareUnsigned(a4, b4) < 0 ? 1 : 0);
        long d5 = a5 - b5 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a5, b5) <= 0 ? 1 : 0) : (Long.compareUnsigned(a5, b5) < 0 ? 1 : 0);

        if (borrow != 0) {
            long c;
            d0 = d0 + MOD0; c = Long.compareUnsigned(d0, MOD0) < 0 ? 1 : 0;
            d1 = d1 + MOD1 + c; c = (c != 0) ? (Long.compareUnsigned(d1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(d1, MOD1) < 0 ? 1 : 0);
            d2 = d2 + MOD2 + c; c = (c != 0) ? (Long.compareUnsigned(d2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(d2, MOD2) < 0 ? 1 : 0);
            d3 = d3 + MOD3 + c; c = (c != 0) ? (Long.compareUnsigned(d3, MOD3) <= 0 ? 1 : 0) : (Long.compareUnsigned(d3, MOD3) < 0 ? 1 : 0);
            d4 = d4 + MOD4 + c; c = (c != 0) ? (Long.compareUnsigned(d4, MOD4) <= 0 ? 1 : 0) : (Long.compareUnsigned(d4, MOD4) < 0 ? 1 : 0);
            d5 = d5 + MOD5 + c;
        }
        o[oo] = d0; o[oo + 1] = d1; o[oo + 2] = d2; o[oo + 3] = d3; o[oo + 4] = d4; o[oo + 5] = d5;
    }

    // ------------------------------------------------------------------
    // Montgomery multiply (CIOS, 6 limbs) — port of MontFp381.montMul
    // ------------------------------------------------------------------

    /** {@code o = a * b} (Montgomery). Output may alias either input. */
    public static void mul(long[] o, int oo, long[] a, int ao, long[] b, int bo) {
        long a0 = a[ao], a1 = a[ao + 1], a2 = a[ao + 2], a3 = a[ao + 3], a4 = a[ao + 4], a5 = a[ao + 5];
        long b0 = b[bo], b1 = b[bo + 1], b2 = b[bo + 2], b3 = b[bo + 3], b4 = b[bo + 4], b5 = b[bo + 5];

        long[] c = {0};
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6, m;

        for (int i = 0; i < 6; i++) {
            long ai = switch (i) { case 0 -> a0; case 1 -> a1; case 2 -> a2; case 3 -> a3; case 4 -> a4; default -> a5; };
            c[0] = 0;
            t0 = mac(t0, ai, b0, c); t1 = mac(t1, ai, b1, c); t2 = mac(t2, ai, b2, c);
            t3 = mac(t3, ai, b3, c); t4 = mac(t4, ai, b4, c); t5 = mac(t5, ai, b5, c); t6 = c[0];
            m = t0 * INV;
            c[0] = 0;
            mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
            t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6;
        }
        subModTo(o, oo, t0, t1, t2, t3, t4, t5, 0);
    }

    /** {@code o = a * a}. */
    public static void sqr(long[] o, int oo, long[] a, int ao) {
        mul(o, oo, a, ao, a, ao);
    }

    // ------------------------------------------------------------------
    // internals (ported verbatim from MontFp381)
    // ------------------------------------------------------------------

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

    /** Conditionally subtract p (if carry set or s ≥ p) and write the 6 limbs to {@code o[oo..]}. */
    private static void subModTo(long[] o, int oo, long s0, long s1, long s2, long s3, long s4, long s5, long carry) {
        if (carry != 0 || geqMod(s0, s1, s2, s3, s4, s5)) {
            long borrow;
            long d0 = s0 - MOD0; borrow = Long.compareUnsigned(s0, MOD0) < 0 ? 1 : 0;
            long d1 = s1 - MOD1 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, MOD1) < 0 ? 1 : 0);
            long d2 = s2 - MOD2 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, MOD2) < 0 ? 1 : 0);
            long d3 = s3 - MOD3 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s3, MOD3) <= 0 ? 1 : 0) : (Long.compareUnsigned(s3, MOD3) < 0 ? 1 : 0);
            long d4 = s4 - MOD4 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s4, MOD4) <= 0 ? 1 : 0) : (Long.compareUnsigned(s4, MOD4) < 0 ? 1 : 0);
            long d5 = s5 - MOD5 - borrow;
            o[oo] = d0; o[oo + 1] = d1; o[oo + 2] = d2; o[oo + 3] = d3; o[oo + 4] = d4; o[oo + 5] = d5;
        } else {
            o[oo] = s0; o[oo + 1] = s1; o[oo + 2] = s2; o[oo + 3] = s3; o[oo + 4] = s4; o[oo + 5] = s5;
        }
    }

    private static boolean geqMod(long l0, long l1, long l2, long l3, long l4, long l5) {
        if (Long.compareUnsigned(l5, MOD5) != 0) return Long.compareUnsigned(l5, MOD5) > 0;
        if (Long.compareUnsigned(l4, MOD4) != 0) return Long.compareUnsigned(l4, MOD4) > 0;
        if (Long.compareUnsigned(l3, MOD3) != 0) return Long.compareUnsigned(l3, MOD3) > 0;
        if (Long.compareUnsigned(l2, MOD2) != 0) return Long.compareUnsigned(l2, MOD2) > 0;
        if (Long.compareUnsigned(l1, MOD1) != 0) return Long.compareUnsigned(l1, MOD1) > 0;
        return Long.compareUnsigned(l0, MOD0) >= 0;
    }
}
