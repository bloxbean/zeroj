package com.bloxbean.cardano.zeroj.crypto.field;

import java.math.BigInteger;

/**
 * BN254 base field element (Fp) in Montgomery form using 4 x 64-bit limbs.
 *
 * <p>The BN254 base field prime is:
 * p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
 * (254 bits)</p>
 *
 * <p>This is the field over which G1 and G2 point coordinates are defined.
 * For the scalar field (used by circuit constraints and witnesses), see {@link MontFr254}.</p>
 *
 * @see MontFr254
 */
public final class MontFp254 {

    // BN254 base field modulus p (little-endian 64-bit limbs)
    // p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    static final long MOD0 = 0x3c208c16d87cfd47L;
    static final long MOD1 = 0x97816a916871ca8dL;
    static final long MOD2 = 0xb85045b68181585dL;
    static final long MOD3 = 0x30644e72e131a029L;

    // Montgomery constant: -p^{-1} mod 2^64
    static final long INV = 0x87d20782e4866389L;

    // R mod p = 2^256 mod p (Montgomery form of 1)
    static final long RONE0 = 0xd35d438dc58f0d9dL;
    static final long RONE1 = 0x0a78eb28f5c70b3dL;
    static final long RONE2 = 0x666ea36f7879462cL;
    static final long RONE3 = 0x0e0a77c19a07df2fL;

    // R^2 mod p = (2^256)^2 mod p (used for toMontgomery conversion)
    static final long R2MOD0 = 0xf32cfc5b538afa89L;
    static final long R2MOD1 = 0xb5e71911d44501fbL;
    static final long R2MOD2 = 0x47ab1eff0a417ff6L;
    static final long R2MOD3 = 0x06d89f71cab8351fL;

    final long l0, l1, l2, l3;

    private MontFp254(long l0, long l1, long l2, long l3) {
        this.l0 = l0;
        this.l1 = l1;
        this.l2 = l2;
        this.l3 = l3;
    }

    // --- Constants ---

    public static final MontFp254 ZERO = new MontFp254(0, 0, 0, 0);
    public static final MontFp254 ONE = new MontFp254(RONE0, RONE1, RONE2, RONE3);
    public static final MontFp254 TWO = ONE.add(ONE);
    public static final MontFp254 THREE = TWO.add(ONE);

    // --- Factory methods ---

    public static MontFp254 fromBigInteger(BigInteger val) {
        val = val.mod(modulus());
        BigInteger mask64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        long limb0 = val.and(mask64).longValue();
        long limb1 = val.shiftRight(64).and(mask64).longValue();
        long limb2 = val.shiftRight(128).and(mask64).longValue();
        long limb3 = val.shiftRight(192).and(mask64).longValue();
        return new MontFp254(limb0, limb1, limb2, limb3).toMontgomery();
    }

    /** @param val non-negative value */
    public static MontFp254 fromLong(long val) {
        if (val < 0) throw new IllegalArgumentException("fromLong requires non-negative value, got " + val);
        if (val == 0) return ZERO;
        if (val == 1) return ONE;
        return new MontFp254(val, 0, 0, 0).toMontgomery();
    }

    static MontFp254 fromMontLimbs(long l0, long l1, long l2, long l3) {
        return new MontFp254(l0, l1, l2, l3);
    }

    // --- Arithmetic ---

    public MontFp254 add(MontFp254 other) {
        long a0 = this.l0, a1 = this.l1, a2 = this.l2, a3 = this.l3;
        long b0 = other.l0, b1 = other.l1, b2 = other.l2, b3 = other.l3;

        long s0 = a0 + b0;
        long c = Long.compareUnsigned(s0, a0) < 0 ? 1 : 0;
        long s1 = a1 + b1 + c;
        c = (c != 0) ? (Long.compareUnsigned(s1, a1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, a1) < 0 ? 1 : 0);
        long s2 = a2 + b2 + c;
        c = (c != 0) ? (Long.compareUnsigned(s2, a2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, a2) < 0 ? 1 : 0);
        long s3 = a3 + b3 + c;
        c = (c != 0) ? (Long.compareUnsigned(s3, a3) <= 0 ? 1 : 0) : (Long.compareUnsigned(s3, a3) < 0 ? 1 : 0);

        return subtractModIfNeeded(s0, s1, s2, s3, c);
    }

    public MontFp254 sub(MontFp254 other) {
        long a0 = this.l0, a1 = this.l1, a2 = this.l2, a3 = this.l3;
        long b0 = other.l0, b1 = other.l1, b2 = other.l2, b3 = other.l3;

        long d0 = a0 - b0;
        long borrow = Long.compareUnsigned(a0, b0) < 0 ? 1 : 0;
        long d1 = a1 - b1 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a1, b1) <= 0 ? 1 : 0) : (Long.compareUnsigned(a1, b1) < 0 ? 1 : 0);
        long d2 = a2 - b2 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a2, b2) <= 0 ? 1 : 0) : (Long.compareUnsigned(a2, b2) < 0 ? 1 : 0);
        long d3 = a3 - b3 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a3, b3) <= 0 ? 1 : 0) : (Long.compareUnsigned(a3, b3) < 0 ? 1 : 0);

        if (borrow != 0) {
            long c = 0;
            d0 = d0 + MOD0; c = Long.compareUnsigned(d0, MOD0) < 0 ? 1 : 0;
            d1 = d1 + MOD1 + c; c = (c != 0) ? (Long.compareUnsigned(d1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(d1, MOD1) < 0 ? 1 : 0);
            d2 = d2 + MOD2 + c; c = (c != 0) ? (Long.compareUnsigned(d2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(d2, MOD2) < 0 ? 1 : 0);
            d3 = d3 + MOD3 + c;
        }
        return new MontFp254(d0, d1, d2, d3);
    }

    public MontFp254 neg() {
        if (isZero()) return this;
        return ZERO.sub(this);
    }

    public MontFp254 mul(MontFp254 other) {
        return montMul(this.l0, this.l1, this.l2, this.l3,
                other.l0, other.l1, other.l2, other.l3);
    }

    public MontFp254 square() {
        return mul(this);
    }

    /** Double this element (add to itself — slightly cheaper than general add). */
    public MontFp254 dbl() {
        return add(this);
    }

    public MontFp254 inverse() {
        if (isZero()) throw new ArithmeticException("Cannot invert zero");
        BigInteger val = toBigInteger();
        BigInteger inv = val.modInverse(modulus());
        return fromBigInteger(inv);
    }

    public MontFp254 pow(BigInteger exp) {
        if (exp.signum() == 0) return ONE;
        MontFp254 result = ONE;
        MontFp254 base = this;
        for (int i = exp.bitLength() - 1; i >= 0; i--) {
            result = result.square();
            if (exp.testBit(i)) result = result.mul(base);
        }
        return result;
    }

    // --- Queries ---

    public boolean isZero() { return l0 == 0 && l1 == 0 && l2 == 0 && l3 == 0; }

    public boolean isOne() { return l0 == RONE0 && l1 == RONE1 && l2 == RONE2 && l3 == RONE3; }

    // --- Conversion ---

    private MontFp254 toMontgomery() {
        return montMul(l0, l1, l2, l3, R2MOD0, R2MOD1, R2MOD2, R2MOD3);
    }

    private MontFp254 fromMontgomery() {
        return montMul(l0, l1, l2, l3, 1, 0, 0, 0);
    }

    public BigInteger toBigInteger() {
        MontFp254 normal = fromMontgomery();
        return MontUtil.limbsToBigInteger(normal.l0, normal.l1, normal.l2, normal.l3);
    }

    /** Cached modulus as BigInteger. */
    private static final BigInteger MODULUS =
            new BigInteger("21888242871839275222246405745257275088696311157297823662689037894645226208583");

    public static BigInteger modulus() {
        return MODULUS;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MontFp254 o)) return false;
        return l0 == o.l0 && l1 == o.l1 && l2 == o.l2 && l3 == o.l3;
    }

    @Override
    public int hashCode() {
        long h = l0 ^ (l1 * 31) ^ (l2 * 997) ^ (l3 * 65537);
        return (int) (h ^ (h >>> 32));
    }

    @Override
    public String toString() { return toBigInteger().toString(); }

    // --- Montgomery multiplication (CIOS) ---

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

    private static MontFp254 montMul(long a0, long a1, long a2, long a3,
                                      long b0, long b1, long b2, long b3) {
        long[] c = {0};
        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

        c[0] = 0; t0 = mac(t0, a0, b0, c); t1 = mac(t1, a0, b1, c); t2 = mac(t2, a0, b2, c); t3 = mac(t3, a0, b3, c); t4 = c[0];
        long m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c); t3 = c[0] + t4; t4 = 0;

        c[0] = 0; t0 = mac(t0, a1, b0, c); t1 = mac(t1, a1, b1, c); t2 = mac(t2, a1, b2, c); t3 = mac(t3, a1, b3, c); t4 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c); t3 = c[0] + t4; t4 = 0;

        c[0] = 0; t0 = mac(t0, a2, b0, c); t1 = mac(t1, a2, b1, c); t2 = mac(t2, a2, b2, c); t3 = mac(t3, a2, b3, c); t4 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c); t3 = c[0] + t4; t4 = 0;

        c[0] = 0; t0 = mac(t0, a3, b0, c); t1 = mac(t1, a3, b1, c); t2 = mac(t2, a3, b2, c); t3 = mac(t3, a3, b3, c); t4 = c[0];
        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c); t3 = c[0] + t4; t4 = 0;

        return subtractModIfNeeded(t0, t1, t2, t3, 0);
    }

    private static MontFp254 subtractModIfNeeded(long s0, long s1, long s2, long s3, long carry) {
        if (carry != 0 || geqMod(s0, s1, s2, s3)) {
            long borrow = 0;
            long d0 = s0 - MOD0; borrow = Long.compareUnsigned(s0, MOD0) < 0 ? 1 : 0;
            long d1 = s1 - MOD1 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s1, MOD1) <= 0 ? 1 : 0) : (Long.compareUnsigned(s1, MOD1) < 0 ? 1 : 0);
            long d2 = s2 - MOD2 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s2, MOD2) <= 0 ? 1 : 0) : (Long.compareUnsigned(s2, MOD2) < 0 ? 1 : 0);
            long d3 = s3 - MOD3 - borrow;
            return new MontFp254(d0, d1, d2, d3);
        }
        return new MontFp254(s0, s1, s2, s3);
    }

    private static boolean geqMod(long l0, long l1, long l2, long l3) {
        if (Long.compareUnsigned(l3, MOD3) != 0) return Long.compareUnsigned(l3, MOD3) > 0;
        if (Long.compareUnsigned(l2, MOD2) != 0) return Long.compareUnsigned(l2, MOD2) > 0;
        if (Long.compareUnsigned(l1, MOD1) != 0) return Long.compareUnsigned(l1, MOD1) > 0;
        return Long.compareUnsigned(l0, MOD0) >= 0;
    }
}
