package com.bloxbean.cardano.zeroj.bls12381.field;

import java.math.BigInteger;

/**
 * BLS12-381 quadratic extension field Fp2 = Fp[u] / (u^2 + 1).
 *
 * <p>An element is (a + b*u) where a, b are in Fp (the BLS12-381 base field).
 * The non-residue is -1, so u^2 = -1.</p>
 *
 * <p>Used for G2 point coordinates on the BLS12-381 twist curve.</p>
 */
public final class MontFp2_381 {

    private final MontFp381 re; // real part (coefficient of 1)
    private final MontFp381 im; // imaginary part (coefficient of u)

    public MontFp2_381(MontFp381 re, MontFp381 im) {
        this.re = re;
        this.im = im;
    }

    // --- Constants ---

    public static final MontFp2_381 ZERO = new MontFp2_381(MontFp381.ZERO, MontFp381.ZERO);
    public static final MontFp2_381 ONE = new MontFp2_381(MontFp381.ONE, MontFp381.ZERO);

    // --- Factory ---

    public static MontFp2_381 of(MontFp381 re, MontFp381 im) {
        return new MontFp2_381(re, im);
    }

    public static MontFp2_381 of(BigInteger re, BigInteger im) {
        return new MontFp2_381(MontFp381.fromBigInteger(re), MontFp381.fromBigInteger(im));
    }

    public static MontFp2_381 of(long re, long im) {
        return new MontFp2_381(MontFp381.fromLong(re), MontFp381.fromLong(im));
    }

    // --- Accessors ---

    public MontFp381 re() { return re; }
    public MontFp381 im() { return im; }

    // --- Arithmetic ---

    public MontFp2_381 add(MontFp2_381 other) {
        return new MontFp2_381(re.add(other.re), im.add(other.im));
    }

    public MontFp2_381 sub(MontFp2_381 other) {
        return new MontFp2_381(re.sub(other.re), im.sub(other.im));
    }

    public MontFp2_381 neg() {
        return new MontFp2_381(re.neg(), im.neg());
    }

    public MontFp2_381 dbl() {
        return new MontFp2_381(re.dbl(), im.dbl());
    }

    /**
     * Karatsuba multiplication: (a+bu)(c+du) = (ac-bd) + ((a+b)(c+d)-ac-bd)u
     * Cost: 3M_Fp (vs 4M_Fp for schoolbook)
     */
    public MontFp2_381 mul(MontFp2_381 other) {
        var ac = re.mul(other.re);
        var bd = im.mul(other.im);
        var abcd = re.add(im).mul(other.re.add(other.im));
        return new MontFp2_381(ac.sub(bd), abcd.sub(ac).sub(bd));
    }

    /**
     * Complex squaring: (a+bu)^2 = (a^2-b^2) + 2ab*u = (a+b)(a-b) + 2ab*u
     * Cost: 2M_Fp
     */
    public MontFp2_381 square() {
        var ab = re.mul(im);
        var apb = re.add(im);
        var amb = re.sub(im);
        return new MontFp2_381(apb.mul(amb), ab.dbl());
    }

    /**
     * Conjugate: conj(a + bu) = a - bu.
     */
    public MontFp2_381 conjugate() {
        return new MontFp2_381(re, im.neg());
    }

    /**
     * Norm: N(a+bu) = a^2 + b^2 (since u^2 = -1)
     */
    public MontFp381 norm() {
        return re.square().add(im.square());
    }

    /**
     * Inverse: (a+bu)^{-1} = conj / norm = (a-bu) / (a^2+b^2)
     */
    public MontFp2_381 inverse() {
        var n = norm().inverse();
        return new MontFp2_381(re.mul(n), im.neg().mul(n));
    }

    /** Multiply by a scalar in Fp. */
    public MontFp2_381 mulScalar(MontFp381 s) {
        return new MontFp2_381(re.mul(s), im.mul(s));
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
        if (!(obj instanceof MontFp2_381 o)) return false;
        return re.equals(o.re) && im.equals(o.im);
    }

    @Override
    public int hashCode() { return re.hashCode() * 31 + im.hashCode(); }

    @Override
    public String toString() { return "(" + re.toBigInteger() + " + " + im.toBigInteger() + "*u)"; }
}
