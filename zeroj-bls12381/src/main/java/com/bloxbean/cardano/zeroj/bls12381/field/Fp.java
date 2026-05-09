package com.bloxbean.cardano.zeroj.bls12381.field;

import java.math.BigInteger;
import java.util.Optional;

/**
 * BLS12-381 base field element — arithmetic modulo the base field prime p.
 *
 * <p>p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab</p>
 */
public record Fp(BigInteger value) {

    /** BLS12-381 base field prime (381 bits). */
    public static final BigInteger P = new BigInteger(
            "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
    private static final BigInteger SQRT_EXPONENT = P.add(BigInteger.ONE).shiftRight(2);
    private static final BigInteger LEXICOGRAPHIC_LIMIT = P.subtract(BigInteger.ONE).shiftRight(1);

    public static final Fp ZERO = new Fp(BigInteger.ZERO);
    public static final Fp ONE = new Fp(BigInteger.ONE);

    public Fp { value = value.mod(P); }

    public static Fp of(BigInteger v) { return new Fp(v); }
    public static Fp of(long v) { return new Fp(BigInteger.valueOf(v)); }
    public static Fp of(String decimal) { return new Fp(new BigInteger(decimal)); }

    public Fp add(Fp o) { return new Fp(value.add(o.value)); }
    public Fp sub(Fp o) { return new Fp(value.subtract(o.value).add(P)); }
    public Fp mul(Fp o) { return new Fp(value.multiply(o.value)); }
    public Fp div(Fp o) { return mul(o.inv()); }
    public Fp neg() { return value.signum() == 0 ? this : new Fp(P.subtract(value)); }
    public Fp inv() { return new Fp(value.modInverse(P)); }
    public Fp square() { return new Fp(value.multiply(value)); }
    public Fp pow(BigInteger exp) { return new Fp(value.modPow(exp, P)); }
    public Optional<Fp> sqrt() {
        var root = pow(SQRT_EXPONENT);
        return root.square().equals(this) ? Optional.of(root) : Optional.empty();
    }
    public boolean isZero() { return value.signum() == 0; }
    public boolean sgn0() { return value.testBit(0); }
    public boolean lexicographicallyLargest() { return value.compareTo(LEXICOGRAPHIC_LIMIT) > 0; }

    @Override public String toString() { return value.toString(); }
}
