package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import java.math.BigInteger;

/**
 * Host-side (out-of-circuit) Ed25519 group arithmetic over the twisted Edwards curve
 * {@code -x² + y² = 1 + d·x²·y²} on {@code GF(2^255-19)} (RFC 8032). Pure {@link BigInteger}.
 *
 * <p>Two roles: (1) it generates the compile-time {@code [2^i]·B} constants the in-circuit
 * fixed-base scalar-multiplication gadget consumes, and (2) it is an independent correctness
 * oracle for {@link Ed25519PointTest}. Because the in-circuit result is additionally validated
 * against authoritative RFC 8032 public-key vectors, any error here surfaces as a failing test.</p>
 */
public final class Ed25519Host {

    private Ed25519Host() {}

    /** p = 2^255 - 19. */
    public static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    /** Curve constant d = -121665/121666 mod p. */
    public static final BigInteger D = new BigInteger(
            "37095705934669439343138083508754565189542113879843219016388785533085940283555");
    /** Base point B. */
    public static final BigInteger BX = new BigInteger(
            "15112221349535400772501151409588531511454012693041857206046113283949847762202");
    public static final BigInteger BY = new BigInteger(
            "46316835694926478169428394003475163141307993866256225615783033603165251855960");

    /** Affine point (x, y). */
    public record Affine(BigInteger x, BigInteger y) {}

    public static final Affine B = new Affine(BX, BY);
    public static final Affine IDENTITY = new Affine(BigInteger.ZERO, BigInteger.ONE);

    private static BigInteger m(BigInteger a) {
        BigInteger r = a.mod(P);
        return r.signum() < 0 ? r.add(P) : r;
    }

    /** Complete twisted-Edwards addition (a = -1). */
    public static Affine add(Affine p1, Affine p2) {
        BigInteger x1 = p1.x, y1 = p1.y, x2 = p2.x, y2 = p2.y;
        BigInteger dxy = m(D.multiply(x1).multiply(x2).multiply(y1).multiply(y2));
        BigInteger xNum = m(x1.multiply(y2).add(y1.multiply(x2)));
        BigInteger xDen = m(BigInteger.ONE.add(dxy));
        BigInteger yNum = m(y1.multiply(y2).add(x1.multiply(x2)));   // + because a = -1: y1y2 - a x1x2 = y1y2 + x1x2
        BigInteger yDen = m(BigInteger.ONE.subtract(dxy));
        BigInteger x3 = m(xNum.multiply(xDen.modInverse(P)));
        BigInteger y3 = m(yNum.multiply(yDen.modInverse(P)));
        return new Affine(x3, y3);
    }

    public static Affine dbl(Affine p) {
        return add(p, p);
    }

    /** scalar · B (base point), for host cross-checks. */
    public static Affine scalarMulBase(BigInteger k) {
        Affine acc = IDENTITY;
        Affine cur = B;
        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) acc = add(acc, cur);
            cur = dbl(cur);
        }
        return acc;
    }

    /** Precompute [2^i]·B for i = 0..n-1 (the fixed-base table). */
    public static Affine[] precompDoublingsOfB(int n) {
        Affine[] out = new Affine[n];
        Affine cur = B;
        for (int i = 0; i < n; i++) {
            out[i] = cur;
            cur = dbl(cur);
        }
        return out;
    }

    /** RFC 8032 point encoding: 32 little-endian bytes of y, top bit = x mod 2. */
    public static byte[] encode(Affine pt) {
        byte[] out = new byte[32];
        BigInteger y = m(pt.y);
        for (int i = 0; i < 32; i++) out[i] = (byte) (y.shiftRight(8 * i).intValue() & 0xff);
        if (pt.x.testBit(0)) out[31] |= (byte) 0x80;
        return out;
    }

    /** RFC 8032 scalar clamp of a 32-byte little-endian buffer's low half. */
    public static BigInteger clampScalar(byte[] lower32) {
        byte[] h = lower32.clone();
        h[0] &= (byte) 0xF8;
        h[31] &= (byte) 0x7F;
        h[31] |= (byte) 0x40;
        BigInteger k = BigInteger.ZERO;
        for (int i = 0; i < 32; i++) k = k.add(BigInteger.valueOf(h[i] & 0xff).shiftLeft(8 * i));
        return k;
    }
}
