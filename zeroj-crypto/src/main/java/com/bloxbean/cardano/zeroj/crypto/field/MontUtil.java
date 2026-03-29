package com.bloxbean.cardano.zeroj.crypto.field;

import java.math.BigInteger;

/**
 * Shared utilities for Montgomery-form field element conversions.
 */
final class MontUtil {

    private MontUtil() {}

    /**
     * Convert 4 unsigned 64-bit limbs (little-endian) to BigInteger.
     */
    static BigInteger limbsToBigInteger(long l0, long l1, long l2, long l3) {
        BigInteger result = toUnsignedBigInteger(l3);
        result = result.shiftLeft(64).or(toUnsignedBigInteger(l2));
        result = result.shiftLeft(64).or(toUnsignedBigInteger(l1));
        result = result.shiftLeft(64).or(toUnsignedBigInteger(l0));
        return result;
    }

    static BigInteger toUnsignedBigInteger(long v) {
        if (v >= 0) return BigInteger.valueOf(v);
        return BigInteger.valueOf(v >>> 1).shiftLeft(1).or(BigInteger.valueOf(v & 1));
    }
}
