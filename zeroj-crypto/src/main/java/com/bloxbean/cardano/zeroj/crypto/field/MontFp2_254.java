package com.bloxbean.cardano.zeroj.crypto.field;

import java.math.BigInteger;

/**
 * BN254 quadratic extension field Fp2 = Fp[u] / (u^2 + 1).
 *
 * <p>An element is (a + b*u) where a, b are in Fp (the BN254 base field).
 * The non-residue is -1, so u^2 = -1.</p>
 *
 * <p>Used for G2 point coordinates on the BN254 twist curve.</p>
 */
public final class MontFp2_254 {

    private final MontFp254 re; // real part (coefficient of 1)
    private final MontFp254 im; // imaginary part (coefficient of u)

    public MontFp2_254(MontFp254 re, MontFp254 im) {
        this.re = re;
        this.im = im;
    }

    // --- Constants ---

    public static final MontFp2_254 ZERO = new MontFp2_254(MontFp254.ZERO, MontFp254.ZERO);
    public static final MontFp2_254 ONE = new MontFp2_254(MontFp254.ONE, MontFp254.ZERO);

    // --- Factory ---

    public static MontFp2_254 of(MontFp254 re, MontFp254 im) {
        return new MontFp2_254(re, im);
    }

    public static MontFp2_254 of(BigInteger re, BigInteger im) {
        return new MontFp2_254(MontFp254.fromBigInteger(re), MontFp254.fromBigInteger(im));
    }

    public static MontFp2_254 of(long re, long im) {
        return new MontFp2_254(MontFp254.fromLong(re), MontFp254.fromLong(im));
    }

    // --- Accessors ---

    public MontFp254 re() { return re; }
    public MontFp254 im() { return im; }

    // --- Arithmetic ---

    public MontFp2_254 add(MontFp2_254 other) {
        return new MontFp2_254(re.add(other.re), im.add(other.im));
    }

    public MontFp2_254 sub(MontFp2_254 other) {
        return new MontFp2_254(re.sub(other.re), im.sub(other.im));
    }

    public MontFp2_254 neg() {
        return new MontFp2_254(re.neg(), im.neg());
    }

    public MontFp2_254 dbl() {
        return new MontFp2_254(re.dbl(), im.dbl());
    }

    /**
     * Karatsuba multiplication: (a+bu)(c+du) = (ac-bd) + ((a+b)(c+d)-ac-bd)u
     * Cost: 3M_Fp (vs 4M_Fp for schoolbook)
     */
    public MontFp2_254 mul(MontFp2_254 other) {
        var ac = re.mul(other.re);
        var bd = im.mul(other.im);
        var abcd = re.add(im).mul(other.re.add(other.im));
        return new MontFp2_254(ac.sub(bd), abcd.sub(ac).sub(bd));
    }

    /**
     * Complex squaring: (a+bu)^2 = (a^2-b^2) + 2ab*u = (a+b)(a-b) + 2ab*u
     * Cost: 2M_Fp
     */
    public MontFp2_254 square() {
        var ab = re.mul(im);
        var apb = re.add(im);
        var amb = re.sub(im);
        return new MontFp2_254(apb.mul(amb), ab.dbl());
    }

    /**
     * Conjugate: conj(a + bu) = a - bu.
     */
    public MontFp2_254 conjugate() {
        return new MontFp2_254(re, im.neg());
    }

    /**
     * Norm: N(a+bu) = a^2 + b^2 (since u^2 = -1, norm = a*conj(a) = a^2-(-1)*b^2)
     */
    public MontFp254 norm() {
        return re.square().add(im.square());
    }

    /**
     * Inverse: (a+bu)^{-1} = conj / norm = (a-bu) / (a^2+b^2)
     */
    public MontFp2_254 inverse() {
        var n = norm().inverse();
        return new MontFp2_254(re.mul(n), im.neg().mul(n));
    }

    /** Multiply by a scalar in Fp. */
    public MontFp2_254 mulScalar(MontFp254 s) {
        return new MontFp2_254(re.mul(s), im.mul(s));
    }

    // --- Queries ---

    public boolean isZero() { return re.isZero() && im.isZero(); }
    public boolean isOne() { return re.isOne() && im.isZero(); }

    // --- Conversion ---

    public BigInteger reBigInt() { return re.toBigInteger(); }
    public BigInteger imBigInt() { return im.toBigInteger(); }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof MontFp2_254 o)) return false;
        return re.equals(o.re) && im.equals(o.im);
    }

    @Override
    public int hashCode() { return re.hashCode() * 31 + im.hashCode(); }

    @Override
    public String toString() { return "(" + re.toBigInteger() + " + " + im.toBigInteger() + "*u)"; }
}
