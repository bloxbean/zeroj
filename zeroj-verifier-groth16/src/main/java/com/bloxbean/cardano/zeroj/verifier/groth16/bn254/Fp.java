package com.bloxbean.cardano.zeroj.verifier.groth16.bn254;

import java.math.BigInteger;

/**
 * BN254 base field element (Fp) — arithmetic modulo the base field prime p.
 *
 * <p>p = 21888242871839275222246405745257275088696311157297823662689037894645226208583</p>
 */
public record Fp(BigInteger value) {

    /** BN254 base field prime. */
    public static final BigInteger P = new BigInteger(
            "21888242871839275222246405745257275088696311157297823662689037894645226208583");

    public static final Fp ZERO = new Fp(BigInteger.ZERO);
    public static final Fp ONE = new Fp(BigInteger.ONE);

    public Fp {
        // Reduce mod p on construction
        value = value.mod(P);
    }

    public static Fp of(BigInteger v) {
        return new Fp(v);
    }

    public static Fp of(long v) {
        return new Fp(BigInteger.valueOf(v));
    }

    public static Fp of(String decimal) {
        return new Fp(new BigInteger(decimal));
    }

    public Fp add(Fp other) {
        return new Fp(value.add(other.value));
    }

    public Fp sub(Fp other) {
        return new Fp(value.subtract(other.value).add(P));
    }

    public Fp mul(Fp other) {
        return new Fp(value.multiply(other.value));
    }

    public Fp neg() {
        if (value.signum() == 0) return this;
        return new Fp(P.subtract(value));
    }

    public Fp inv() {
        if (value.signum() == 0) {
            throw new ArithmeticException("Cannot invert zero");
        }
        return new Fp(value.modInverse(P));
    }

    public Fp square() {
        return new Fp(value.multiply(value));
    }

    public Fp pow(BigInteger exp) {
        return new Fp(value.modPow(exp, P));
    }

    public boolean isZero() {
        return value.signum() == 0;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
