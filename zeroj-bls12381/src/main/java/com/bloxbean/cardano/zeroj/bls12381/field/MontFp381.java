package com.bloxbean.cardano.zeroj.bls12381.field;

import java.math.BigInteger;

/**
 * BLS12-381 base field element (Fp) in Montgomery form using 6 x 64-bit limbs.
 *
 * <p>The BLS12-381 base field prime is:
 * p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
 * (381 bits)</p>
 *
 * <p>This is the field over which G1 and G2 point coordinates are defined.
 * For the scalar field (used by circuit constraints and witnesses), see {@link MontFr381}.</p>
 *
 * @see MontFr381
 */
public final class MontFp381 {

    // BLS12-381 base field modulus p (little-endian 64-bit limbs)
    static final long MOD0 = 0xb9feffffffffaaabL;
    static final long MOD1 = 0x1eabfffeb153ffffL;
    static final long MOD2 = 0x6730d2a0f6b0f624L;
    static final long MOD3 = 0x64774b84f38512bfL;
    static final long MOD4 = 0x4b1ba7b6434bacd7L;
    static final long MOD5 = 0x1a0111ea397fe69aL;

    // Montgomery constant: -p^{-1} mod 2^64
    static final long INV = 0x89f3fffcfffcfffdL;

    // R mod p = 2^384 mod p (Montgomery form of 1)
    static final long RONE0 = 0x760900000002fffdL;
    static final long RONE1 = 0xebf4000bc40c0002L;
    static final long RONE2 = 0x5f48985753c758baL;
    static final long RONE3 = 0x77ce585370525745L;
    static final long RONE4 = 0x5c071a97a256ec6dL;
    static final long RONE5 = 0x15f65ec3fa80e493L;

    // R^2 mod p = (2^384)^2 mod p (used for toMontgomery conversion)
    static final long R2MOD0 = 0xf4df1f341c341746L;
    static final long R2MOD1 = 0x0a76e6a609d104f1L;
    static final long R2MOD2 = 0x8de5476c4c95b6d5L;
    static final long R2MOD3 = 0x67eb88a9939d83c0L;
    static final long R2MOD4 = 0x9a793e85b519952dL;
    static final long R2MOD5 = 0x11988fe592cae3aaL;

    final long l0, l1, l2, l3, l4, l5;

    private MontFp381(long l0, long l1, long l2, long l3, long l4, long l5) {
        this.l0 = l0;
        this.l1 = l1;
        this.l2 = l2;
        this.l3 = l3;
        this.l4 = l4;
        this.l5 = l5;
    }

    // --- Limb accessors (for serialization) ---

    /**
     * Returns the 6 Montgomery-form limbs as a long array (little-endian: l0 is least significant).
     */
    public long[] toLimbs() {
        return new long[]{l0, l1, l2, l3, l4, l5};
    }

    // --- Constants ---

    public static final MontFp381 ZERO = new MontFp381(0, 0, 0, 0, 0, 0);
    public static final MontFp381 ONE = new MontFp381(RONE0, RONE1, RONE2, RONE3, RONE4, RONE5);
    public static final MontFp381 TWO = ONE.add(ONE);
    public static final MontFp381 THREE = TWO.add(ONE);

    // --- Factory methods ---

    public static MontFp381 fromBigInteger(BigInteger val) {
        val = val.mod(modulus());
        BigInteger mask64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        long limb0 = val.and(mask64).longValue();
        long limb1 = val.shiftRight(64).and(mask64).longValue();
        long limb2 = val.shiftRight(128).and(mask64).longValue();
        long limb3 = val.shiftRight(192).and(mask64).longValue();
        long limb4 = val.shiftRight(256).and(mask64).longValue();
        long limb5 = val.shiftRight(320).and(mask64).longValue();
        return new MontFp381(limb0, limb1, limb2, limb3, limb4, limb5).toMontgomery();
    }

    /** @param val non-negative value */
    public static MontFp381 fromLong(long val) {
        if (val < 0) throw new IllegalArgumentException("fromLong requires non-negative value, got " + val);
        if (val == 0) return ZERO;
        if (val == 1) return ONE;
        return new MontFp381(val, 0, 0, 0, 0, 0).toMontgomery();
    }

    /**
     * Creates a MontFp381 from 6 Montgomery-form limbs (little-endian: l0 is least significant).
     * The limbs must already be in Montgomery form — no conversion is performed.
     * The represented Montgomery residue must be canonical ({@code < p}).
     */
    public static MontFp381 fromMontLimbs(long l0, long l1, long l2, long l3, long l4, long l5) {
        if (geqMod(l0, l1, l2, l3, l4, l5)) {
            throw new IllegalArgumentException("Montgomery Fp limbs must be canonical");
        }
        return new MontFp381(l0, l1, l2, l3, l4, l5);
    }

    // --- Arithmetic ---

    public MontFp381 add(MontFp381 other) {
        long a0 = this.l0, a1 = this.l1, a2 = this.l2, a3 = this.l3, a4 = this.l4, a5 = this.l5;
        long b0 = other.l0, b1 = other.l1, b2 = other.l2, b3 = other.l3, b4 = other.l4, b5 = other.l5;

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

        return subtractModIfNeeded(s0, s1, s2, s3, s4, s5, c);
    }

    public MontFp381 sub(MontFp381 other) {
        long a0 = this.l0, a1 = this.l1, a2 = this.l2, a3 = this.l3, a4 = this.l4, a5 = this.l5;
        long b0 = other.l0, b1 = other.l1, b2 = other.l2, b3 = other.l3, b4 = other.l4, b5 = other.l5;

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
            long c = 0;
            d0 = d0 + MOD0; c = Long.compareUnsigned(d0, MOD0) < 0 ? 1 : 0;
            d1 = d1 + MOD1 + c; c = (c != 0) ? (Long.compareUnsigned(d1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(d1, MOD1) < 0 ? 1 : 0);
            d2 = d2 + MOD2 + c; c = (c != 0) ? (Long.compareUnsigned(d2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(d2, MOD2) < 0 ? 1 : 0);
            d3 = d3 + MOD3 + c; c = (c != 0) ? (Long.compareUnsigned(d3, MOD3) <= 0 ? 1 : 0) : (Long.compareUnsigned(d3, MOD3) < 0 ? 1 : 0);
            d4 = d4 + MOD4 + c; c = (c != 0) ? (Long.compareUnsigned(d4, MOD4) <= 0 ? 1 : 0) : (Long.compareUnsigned(d4, MOD4) < 0 ? 1 : 0);
            d5 = d5 + MOD5 + c;
        }
        return new MontFp381(d0, d1, d2, d3, d4, d5);
    }

    public MontFp381 neg() {
        if (isZero()) return this;
        return ZERO.sub(this);
    }

    public MontFp381 mul(MontFp381 other) {
        return montMul(this.l0, this.l1, this.l2, this.l3, this.l4, this.l5,
                other.l0, other.l1, other.l2, other.l3, other.l4, other.l5);
    }

    public MontFp381 square() {
        return mul(this);
    }

    /** Double this element (add to itself). */
    public MontFp381 dbl() {
        return add(this);
    }

    /**
     * Field inversion via Fermat's little theorem: a^{-1} = a^{p-2} mod p.
     *
     * <p>Uses a fixed public exponent ({@code p - 2}). This keeps the exponent schedule
     * independent of the input value, but the pure-Java field operations are not a full
     * JVM constant-time guarantee.</p>
     */
    public MontFp381 inverse() {
        if (isZero()) throw new ArithmeticException("Cannot invert zero");
        // a^{p-2} mod p via binary exponentiation with fixed bit-length
        return pow(modulus().subtract(BigInteger.TWO));
    }

    public MontFp381 pow(BigInteger exp) {
        if (exp.signum() == 0) return ONE;
        MontFp381 result = ONE;
        MontFp381 base = this;
        for (int i = exp.bitLength() - 1; i >= 0; i--) {
            result = result.square();
            if (exp.testBit(i)) result = result.mul(base);
        }
        return result;
    }

    // --- Queries ---

    public boolean isZero() { return l0 == 0 && l1 == 0 && l2 == 0 && l3 == 0 && l4 == 0 && l5 == 0; }

    public boolean isOne() {
        return l0 == RONE0 && l1 == RONE1 && l2 == RONE2 && l3 == RONE3 && l4 == RONE4 && l5 == RONE5;
    }

    // --- Conversion ---

    private MontFp381 toMontgomery() {
        return montMul(l0, l1, l2, l3, l4, l5, R2MOD0, R2MOD1, R2MOD2, R2MOD3, R2MOD4, R2MOD5);
    }

    private MontFp381 fromMontgomery() {
        return montMul(l0, l1, l2, l3, l4, l5, 1, 0, 0, 0, 0, 0);
    }

    public BigInteger toBigInteger() {
        MontFp381 normal = fromMontgomery();
        return MontUtil.limbsToBigInteger(normal.l0, normal.l1, normal.l2, normal.l3, normal.l4, normal.l5);
    }

    private static final BigInteger MODULUS = new BigInteger(
            "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);

    public static BigInteger modulus() {
        return MODULUS;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MontFp381 o)) return false;
        return l0 == o.l0 && l1 == o.l1 && l2 == o.l2 && l3 == o.l3 && l4 == o.l4 && l5 == o.l5;
    }

    @Override
    public int hashCode() {
        long h = l0 ^ (l1 * 31) ^ (l2 * 997) ^ (l3 * 65537) ^ (l4 * 1048583) ^ (l5 * 16777259);
        return (int) (h ^ (h >>> 32));
    }

    @Override
    public String toString() { return toBigInteger().toString(); }

    // --- Montgomery multiplication (CIOS) for 6 limbs ---

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

    @SuppressWarnings("java:S107") // 12 parameters needed for 6-limb CIOS
    private static MontFp381 montMul(long a0, long a1, long a2, long a3, long a4, long a5,
                                      long b0, long b1, long b2, long b3, long b4, long b5) {
        long[] c = {0};
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0;

        // --- Iteration 0: t += a[0] * b ---
        c[0] = 0; t0 = mac(t0, a0, b0, c); t1 = mac(t1, a0, b1, c); t2 = mac(t2, a0, b2, c);
        t3 = mac(t3, a0, b3, c); t4 = mac(t4, a0, b4, c); t5 = mac(t5, a0, b5, c); t6 = c[0];
        long m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
        t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6; t6 = 0;

        // --- Iteration 1: t += a[1] * b ---
        c[0] = 0; t0 = mac(t0, a1, b0, c); t1 = mac(t1, a1, b1, c); t2 = mac(t2, a1, b2, c);
        t3 = mac(t3, a1, b3, c); t4 = mac(t4, a1, b4, c); t5 = mac(t5, a1, b5, c); t6 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
        t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6; t6 = 0;

        // --- Iteration 2: t += a[2] * b ---
        c[0] = 0; t0 = mac(t0, a2, b0, c); t1 = mac(t1, a2, b1, c); t2 = mac(t2, a2, b2, c);
        t3 = mac(t3, a2, b3, c); t4 = mac(t4, a2, b4, c); t5 = mac(t5, a2, b5, c); t6 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
        t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6; t6 = 0;

        // --- Iteration 3: t += a[3] * b ---
        c[0] = 0; t0 = mac(t0, a3, b0, c); t1 = mac(t1, a3, b1, c); t2 = mac(t2, a3, b2, c);
        t3 = mac(t3, a3, b3, c); t4 = mac(t4, a3, b4, c); t5 = mac(t5, a3, b5, c); t6 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
        t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6; t6 = 0;

        // --- Iteration 4: t += a[4] * b ---
        c[0] = 0; t0 = mac(t0, a4, b0, c); t1 = mac(t1, a4, b1, c); t2 = mac(t2, a4, b2, c);
        t3 = mac(t3, a4, b3, c); t4 = mac(t4, a4, b4, c); t5 = mac(t5, a4, b5, c); t6 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
        t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6; t6 = 0;

        // --- Iteration 5: t += a[5] * b ---
        c[0] = 0; t0 = mac(t0, a5, b0, c); t1 = mac(t1, a5, b1, c); t2 = mac(t2, a5, b2, c);
        t3 = mac(t3, a5, b3, c); t4 = mac(t4, a5, b4, c); t5 = mac(t5, a5, b5, c); t6 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c);
        t2 = mac(t3, m, MOD3, c); t3 = mac(t4, m, MOD4, c); t4 = mac(t5, m, MOD5, c); t5 = c[0] + t6; t6 = 0;

        return subtractModIfNeeded(t0, t1, t2, t3, t4, t5, 0);
    }

    private static MontFp381 subtractModIfNeeded(long s0, long s1, long s2, long s3, long s4, long s5, long carry) {
        if (carry != 0 || geqMod(s0, s1, s2, s3, s4, s5)) {
            long borrow = 0;
            long d0 = s0 - MOD0; borrow = Long.compareUnsigned(s0, MOD0) < 0 ? 1 : 0;
            long d1 = s1 - MOD1 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, MOD1) < 0 ? 1 : 0);
            long d2 = s2 - MOD2 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, MOD2) < 0 ? 1 : 0);
            long d3 = s3 - MOD3 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s3, MOD3) <= 0 ? 1 : 0) : (Long.compareUnsigned(s3, MOD3) < 0 ? 1 : 0);
            long d4 = s4 - MOD4 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s4, MOD4) <= 0 ? 1 : 0) : (Long.compareUnsigned(s4, MOD4) < 0 ? 1 : 0);
            long d5 = s5 - MOD5 - borrow;
            return new MontFp381(d0, d1, d2, d3, d4, d5);
        }
        return new MontFp381(s0, s1, s2, s3, s4, s5);
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
