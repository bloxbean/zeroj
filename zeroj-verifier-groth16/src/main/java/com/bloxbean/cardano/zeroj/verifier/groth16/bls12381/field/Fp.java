package com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.field;

import java.math.BigInteger;

/**
 * BLS12-381 base field element — arithmetic modulo the base field prime p.
 *
 * <p>p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab</p>
 */
public record Fp(BigInteger value) {

    /** BLS12-381 base field prime (381 bits). */
    public static final BigInteger P = new BigInteger(
            "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);

    public static final Fp ZERO = new Fp(BigInteger.ZERO);
    public static final Fp ONE = new Fp(BigInteger.ONE);

    public Fp { value = value.mod(P); }

    public static Fp of(BigInteger v) { return new Fp(v); }
    public static Fp of(long v) { return new Fp(BigInteger.valueOf(v)); }
    public static Fp of(String decimal) { return new Fp(new BigInteger(decimal)); }

    public Fp add(Fp o) { return new Fp(value.add(o.value)); }
    public Fp sub(Fp o) { return new Fp(value.subtract(o.value).add(P)); }
    public Fp mul(Fp o) { return new Fp(value.multiply(o.value)); }
    public Fp neg() { return value.signum() == 0 ? this : new Fp(P.subtract(value)); }
    public Fp inv() { return new Fp(value.modInverse(P)); }
    public Fp square() { return new Fp(value.multiply(value)); }
    public Fp pow(BigInteger exp) { return new Fp(value.modPow(exp, P)); }
    public boolean isZero() { return value.signum() == 0; }

    @Override public String toString() { return value.toString(); }
}
