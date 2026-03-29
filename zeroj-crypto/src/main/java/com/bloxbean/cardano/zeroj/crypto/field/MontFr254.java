package com.bloxbean.cardano.zeroj.crypto.field;

import java.math.BigInteger;

/**
 * BN254 scalar field element (Fr) in Montgomery form using 4 x 64-bit limbs.
 *
 * <p>The BN254 scalar field order is:
 * r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 * (254 bits, ~2^253.6)</p>
 *
 * <h3>Montgomery representation</h3>
 * <p>A field element {@code a} is stored as {@code aR mod r} where {@code R = 2^256}.
 * This allows multiplication without expensive trial division: instead of
 * computing {@code a*b mod r} via BigInteger division, we compute
 * {@code montMul(aR, bR) = abR mod r} using only shifts, additions, and
 * a precomputed inverse {@code r' = -r^{-1} mod 2^64}.</p>
 *
 * <h3>Limb layout</h3>
 * <p>The value is stored in 4 unsigned 64-bit limbs in little-endian order:
 * {@code value = l0 + l1*2^64 + l2*2^128 + l3*2^192}.</p>
 *
 * <h3>Performance</h3>
 * <p>Uses {@link Math#unsignedMultiplyHigh} (Java 18+) for 64x64→128 multiplication,
 * avoiding BigInteger allocation entirely in the hot path.</p>
 */
public final class MontFr254 {

    // BN254 scalar field modulus r (little-endian 64-bit limbs)
    // r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    // Hex: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
    static final long MOD0 = 0x43e1f593f0000001L;
    static final long MOD1 = 0x2833e84879b97091L;
    static final long MOD2 = 0xb85045b68181585dL;
    static final long MOD3 = 0x30644e72e131a029L;

    // Montgomery constant: r' = -r^{-1} mod 2^64
    // This satisfies: r * r' ≡ -1 (mod 2^64)
    static final long INV = 0xc2e1f593efffffffL;

    // R mod r = 2^256 mod r (Montgomery form of 1)
    // Precomputed: R_MOD = 2^256 mod r
    static final long RONE0 = 0xac96341c4ffffffbL;
    static final long RONE1 = 0x36fc76959f60cd29L;
    static final long RONE2 = 0x666ea36f7879462eL;
    static final long RONE3 = 0x0e0a77c19a07df2fL;

    // R^2 mod r = (2^256)^2 mod r (used for toMontgomery conversion)
    static final long R2MOD0 = 0x1bb8e645ae216da7L;
    static final long R2MOD1 = 0x53fe3ab1e35c59e3L;
    static final long R2MOD2 = 0x8c49833d53bb8085L;
    static final long R2MOD3 = 0x0216d0b17f4e44a5L;

    /** The four 64-bit limbs in little-endian order. */
    final long l0, l1, l2, l3;

    private MontFr254(long l0, long l1, long l2, long l3) {
        this.l0 = l0;
        this.l1 = l1;
        this.l2 = l2;
        this.l3 = l3;
    }

    // --- Constants ---

    /** The zero element. */
    public static final MontFr254 ZERO = new MontFr254(0, 0, 0, 0);

    /** The one element (in Montgomery form: R mod r). */
    public static final MontFr254 ONE = new MontFr254(RONE0, RONE1, RONE2, RONE3);

    // --- Factory methods ---

    /**
     * Create a field element from a BigInteger value (normal form).
     * Converts to Montgomery representation internally.
     */
    public static MontFr254 fromBigInteger(BigInteger val) {
        val = val.mod(modulus());
        BigInteger mask64 = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);
        long limb0 = val.and(mask64).longValue();
        long limb1 = val.shiftRight(64).and(mask64).longValue();
        long limb2 = val.shiftRight(128).and(mask64).longValue();
        long limb3 = val.shiftRight(192).and(mask64).longValue();
        // Convert to Montgomery form: multiply by R^2 mod r, then Montgomery reduce
        return new MontFr254(limb0, limb1, limb2, limb3).toMontgomery();
    }

    /**
     * Create a field element from a long value.
     */
    public static MontFr254 fromLong(long val) {
        if (val == 0) return ZERO;
        if (val == 1) return ONE;
        // val is in normal form; convert to Montgomery
        return new MontFr254(val, 0, 0, 0).toMontgomery();
    }

    /**
     * Create directly from Montgomery-form limbs (internal use).
     */
    static MontFr254 fromMontLimbs(long l0, long l1, long l2, long l3) {
        return new MontFr254(l0, l1, l2, l3);
    }

    // --- Arithmetic ---

    /**
     * Field addition: (a + b) mod r
     */
    public MontFr254 add(MontFr254 other) {
        // Add limbs with carry propagation
        long a0 = this.l0, a1 = this.l1, a2 = this.l2, a3 = this.l3;
        long b0 = other.l0, b1 = other.l1, b2 = other.l2, b3 = other.l3;

        long s0 = a0 + b0;
        long c = Long.compareUnsigned(s0, a0) < 0 ? 1 : 0;

        long s1 = a1 + b1 + c;
        c = (c != 0) ? (Long.compareUnsigned(s1, a1) <= 0 ? 1 : 0)
                : (Long.compareUnsigned(s1, a1) < 0 ? 1 : 0);

        long s2 = a2 + b2 + c;
        c = (c != 0) ? (Long.compareUnsigned(s2, a2) <= 0 ? 1 : 0)
                : (Long.compareUnsigned(s2, a2) < 0 ? 1 : 0);

        long s3 = a3 + b3 + c;
        c = (c != 0) ? (Long.compareUnsigned(s3, a3) <= 0 ? 1 : 0)
                : (Long.compareUnsigned(s3, a3) < 0 ? 1 : 0);

        // Conditional subtraction: if s >= r, subtract r
        return subtractModIfNeeded(s0, s1, s2, s3, c);
    }

    /**
     * Field subtraction: (a - b) mod r
     */
    public MontFr254 sub(MontFr254 other) {
        long a0 = this.l0, a1 = this.l1, a2 = this.l2, a3 = this.l3;
        long b0 = other.l0, b1 = other.l1, b2 = other.l2, b3 = other.l3;

        long d0 = a0 - b0;
        long borrow = Long.compareUnsigned(a0, b0) < 0 ? 1 : 0;

        long d1 = a1 - b1 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a1, b1) <= 0 ? 1 : 0)
                : (Long.compareUnsigned(a1, b1) < 0 ? 1 : 0);

        long d2 = a2 - b2 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a2, b2) <= 0 ? 1 : 0)
                : (Long.compareUnsigned(a2, b2) < 0 ? 1 : 0);

        long d3 = a3 - b3 - borrow;
        borrow = (borrow != 0) ? (Long.compareUnsigned(a3, b3) <= 0 ? 1 : 0)
                : (Long.compareUnsigned(a3, b3) < 0 ? 1 : 0);

        // If borrow, add modulus
        if (borrow != 0) {
            long c = 0;
            d0 = d0 + MOD0; c = Long.compareUnsigned(d0, MOD0) < 0 ? 1 : 0;
            d1 = d1 + MOD1 + c; c = (c != 0) ? (Long.compareUnsigned(d1, MOD1) <= 0 ? 1 : 0)
                    : (Long.compareUnsigned(d1, MOD1) < 0 ? 1 : 0);
            d2 = d2 + MOD2 + c; c = (c != 0) ? (Long.compareUnsigned(d2, MOD2) <= 0 ? 1 : 0)
                    : (Long.compareUnsigned(d2, MOD2) < 0 ? 1 : 0);
            d3 = d3 + MOD3 + c;
        }
        return new MontFr254(d0, d1, d2, d3);
    }

    /**
     * Field negation: -a mod r
     */
    public MontFr254 neg() {
        if (isZero()) return this;
        return ZERO.sub(this);
    }

    /**
     * Montgomery multiplication: montMul(aR, bR) = abR mod r
     * <p>
     * Uses the CIOS (Coarsely Integrated Operand Scanning) algorithm.
     * Each step: t += a_i * b, then reduce one limb via Montgomery constant.
     */
    public MontFr254 mul(MontFr254 other) {
        return montMul(this.l0, this.l1, this.l2, this.l3,
                other.l0, other.l1, other.l2, other.l3);
    }

    /**
     * Field squaring (uses mul; a dedicated squaring path can be added later).
     */
    public MontFr254 square() {
        return mul(this);
    }

    /**
     * Field inversion: a^{-1} mod r via Fermat's little theorem: a^{r-2} mod r.
     */
    public MontFr254 inverse() {
        if (isZero()) throw new ArithmeticException("Cannot invert zero");
        // r - 2 in hex: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff
        // Use square-and-multiply with the addition chain
        // For now, use the BigInteger path (correct, optimize later with addition chain)
        BigInteger val = toBigInteger();
        BigInteger inv = val.modInverse(modulus());
        return fromBigInteger(inv);
    }

    /**
     * Exponentiation: a^exp mod r. The exponent is treated as unsigned.
     *
     * @param exp non-negative exponent (negative values are rejected)
     */
    public MontFr254 pow(long exp) {
        if (exp < 0) throw new IllegalArgumentException("Exponent must be non-negative, got " + exp);
        if (exp == 0) return ONE;
        if (exp == 1) return this;
        MontFr254 result = ONE;
        MontFr254 base = this;
        while (exp != 0) {
            if ((exp & 1) == 1) result = result.mul(base);
            base = base.square();
            exp >>>= 1;
        }
        return result;
    }

    // --- Queries ---

    public boolean isZero() {
        return l0 == 0 && l1 == 0 && l2 == 0 && l3 == 0;
    }

    public boolean isOne() {
        return l0 == RONE0 && l1 == RONE1 && l2 == RONE2 && l3 == RONE3;
    }

    // --- Conversion ---

    /**
     * Convert from normal form to Montgomery form: a → aR mod r.
     * Implemented as montMul(a, R^2 mod r).
     */
    private MontFr254 toMontgomery() {
        return montMul(l0, l1, l2, l3, R2MOD0, R2MOD1, R2MOD2, R2MOD3);
    }

    /**
     * Convert from Montgomery form back to normal form: aR → a.
     * Implemented as montMul(aR, 1).
     */
    private MontFr254 fromMontgomery() {
        return montMul(l0, l1, l2, l3, 1, 0, 0, 0);
    }

    /**
     * Convert to BigInteger (normal form).
     */
    public BigInteger toBigInteger() {
        MontFr254 normal = fromMontgomery();
        return MontUtil.limbsToBigInteger(normal.l0, normal.l1, normal.l2, normal.l3);
    }

    /**
     * The BN254 scalar field modulus as BigInteger.
     */
    public static BigInteger modulus() {
        return new BigInteger("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MontFr254 o)) return false;
        return l0 == o.l0 && l1 == o.l1 && l2 == o.l2 && l3 == o.l3;
    }

    @Override
    public int hashCode() {
        long h = l0 ^ (l1 * 31) ^ (l2 * 997) ^ (l3 * 65537);
        return (int) (h ^ (h >>> 32));
    }

    @Override
    public String toString() {
        return toBigInteger().toString();
    }

    // --- Montgomery multiplication (CIOS) ---

    /**
     * Unsigned add with carry: returns {sum, carry} packed.
     * sum = (a + b + carryIn) mod 2^64, carry = overflow (0 or 1).
     */
    private static long adc(long a, long b, long[] state) {
        // state[0] = carry in/out
        long sum = a + b + state[0];
        // Detect overflow: if carry_in was 0, overflow iff sum < a
        // if carry_in was 1, overflow iff sum <= a
        if (state[0] != 0) {
            state[0] = Long.compareUnsigned(sum, a) <= 0 ? 1 : 0;
        } else {
            state[0] = Long.compareUnsigned(sum, a) < 0 ? 1 : 0;
        }
        return sum;
    }

    /**
     * Multiply-and-add: acc += a * b, return low 64 bits, carry high 64 bits forward.
     * More precisely: (hi:lo) = a * b; result = lo + acc + carry_in; carry_out = hi + overflow.
     */
    private static long mac(long acc, long a, long b, long[] state) {
        // state[0] = carry in/out
        long lo = a * b;
        long hi = Math.unsignedMultiplyHigh(a, b);
        // lo + acc
        long sum = lo + acc;
        long carry1 = Long.compareUnsigned(sum, lo) < 0 ? 1 : 0;
        // sum + carry_in
        long result = sum + state[0];
        long carry2 = Long.compareUnsigned(result, sum) < 0 ? 1 : 0;
        state[0] = hi + carry1 + carry2;
        return result;
    }

    /**
     * CIOS Montgomery multiplication: computes (a * b * R^{-1}) mod r
     * where a and b are in 4 x 64-bit limbs.
     *
     * <p>Uses Math.unsignedMultiplyHigh for 64x64->128-bit multiplication.</p>
     */
    private static MontFr254 montMul(long a0, long a1, long a2, long a3,
                                      long b0, long b1, long b2, long b3) {
        long[] c = {0}; // carry state

        long t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0;

        // --- Iteration 0: t += a[0] * b ---
        c[0] = 0; t0 = mac(t0, a0, b0, c); t1 = mac(t1, a0, b1, c); t2 = mac(t2, a0, b2, c); t3 = mac(t3, a0, b3, c); t4 = c[0];

        // Montgomery reduction step 0
        long m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c); // discard low word (it's zero by construction)
        t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c);
        c[0] = c[0] + t4; // can't overflow since max value is 2*(r-1) < 2^257
        t3 = c[0];
        t4 = 0; // reset for next iteration

        // --- Iteration 1: t += a[1] * b ---
        c[0] = 0; t0 = mac(t0, a1, b0, c); t1 = mac(t1, a1, b1, c); t2 = mac(t2, a1, b2, c); t3 = mac(t3, a1, b3, c); t4 = c[0];

        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c);
        t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c);
        c[0] = c[0] + t4;
        t3 = c[0];
        t4 = 0;

        // --- Iteration 2: t += a[2] * b ---
        c[0] = 0; t0 = mac(t0, a2, b0, c); t1 = mac(t1, a2, b1, c); t2 = mac(t2, a2, b2, c); t3 = mac(t3, a2, b3, c); t4 = c[0];

        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c);
        t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c);
        c[0] = c[0] + t4;
        t3 = c[0];
        t4 = 0;

        // --- Iteration 3: t += a[3] * b ---
        c[0] = 0; t0 = mac(t0, a3, b0, c); t1 = mac(t1, a3, b1, c); t2 = mac(t2, a3, b2, c); t3 = mac(t3, a3, b3, c); t4 = c[0];

        m = t0 * INV;
        c[0] = 0; mac(t0, m, MOD0, c);
        t0 = mac(t1, m, MOD1, c); t1 = mac(t2, m, MOD2, c); t2 = mac(t3, m, MOD3, c);
        c[0] = c[0] + t4;
        t3 = c[0];
        t4 = 0;

        // Final conditional subtraction
        return subtractModIfNeeded(t0, t1, t2, t3, 0);
    }

    /**
     * If value >= modulus (or carry is set), subtract modulus.
     */
    private static MontFr254 subtractModIfNeeded(long s0, long s1, long s2, long s3, long carry) {
        if (carry != 0 || geqMod(s0, s1, s2, s3)) {
            long borrow = 0;
            long d0 = s0 - MOD0; borrow = Long.compareUnsigned(s0, MOD0) < 0 ? 1 : 0;
            long d1 = s1 - MOD1 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s1, MOD1) <= 0 ? 1 : 0)
                    : (Long.compareUnsigned(s1, MOD1) < 0 ? 1 : 0);
            long d2 = s2 - MOD2 - borrow; borrow = (borrow != 0) ? (Long.compareUnsigned(s2, MOD2) <= 0 ? 1 : 0)
                    : (Long.compareUnsigned(s2, MOD2) < 0 ? 1 : 0);
            long d3 = s3 - MOD3 - borrow;
            return new MontFr254(d0, d1, d2, d3);
        }
        return new MontFr254(s0, s1, s2, s3);
    }

    /**
     * Check if (l0, l1, l2, l3) >= MOD (unsigned comparison, most significant limb first).
     */
    private static boolean geqMod(long l0, long l1, long l2, long l3) {
        if (Long.compareUnsigned(l3, MOD3) != 0) return Long.compareUnsigned(l3, MOD3) > 0;
        if (Long.compareUnsigned(l2, MOD2) != 0) return Long.compareUnsigned(l2, MOD2) > 0;
        if (Long.compareUnsigned(l1, MOD1) != 0) return Long.compareUnsigned(l1, MOD1) > 0;
        return Long.compareUnsigned(l0, MOD0) >= 0;
    }
}
