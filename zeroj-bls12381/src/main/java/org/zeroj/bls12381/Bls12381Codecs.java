package org.zeroj.bls12381;

import org.zeroj.bls12381.ec.G1Point;
import org.zeroj.bls12381.ec.G2Point;
import org.zeroj.bls12381.field.Fp;
import org.zeroj.bls12381.field.Fp2;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * BLS12-381 byte encodings used by ZeroJ providers.
 *
 * <p>G1 uncompressed encoding is {@code x || y}. G2 uncompressed encoding is
 * {@code x.c1 || x.c0 || y.c1 || y.c0}, matching the standard BLS12-381
 * serialization used by zkcrypto/blst.</p>
 */
public final class Bls12381Codecs {
    public static final int FP_BYTES = 48;
    public static final int SCALAR_BYTES = 32;
    public static final int G1_COMPRESSED_BYTES = FP_BYTES;
    public static final int G2_COMPRESSED_BYTES = FP_BYTES * 2;
    public static final int G1_UNCOMPRESSED_BYTES = FP_BYTES * 2;
    public static final int G2_UNCOMPRESSED_BYTES = FP_BYTES * 4;

    private static final int COMPRESSED_FLAG = 0x80;
    private static final int INFINITY_FLAG = 0x40;
    private static final int SORT_FLAG = 0x20;
    private static final int FLAG_MASK = 0xe0;

    private Bls12381Codecs() {}

    public static byte[] scalarToLittleEndian32(BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        if (scalar.signum() < 0 || scalar.compareTo(Bls12381Generators.SCALAR_FIELD_ORDER) >= 0) {
            throw new IllegalArgumentException("Scalar is outside BLS12-381 Fr");
        }
        byte[] be = fixedBigEndian(scalar, SCALAR_BYTES);
        reverse(be);
        return be;
    }

    public static byte[] scalarToLittleEndian32Reduced(BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        return scalarToLittleEndian32(scalar.mod(Bls12381Generators.SCALAR_FIELD_ORDER));
    }

    /**
     * Canonical 32-octet big-endian scalar decoding ({@code I2OSP}/{@code OS2IP}, RFC 9380 §4):
     * exactly 32 octets holding a value in {@code [0, r)}, where {@code r} is the order of G1.
     * Never reduces. The input array is read, not retained.
     *
     * @throws NullPointerException     if {@code bytes} is null
     * @throws IllegalArgumentException if the length is not 32 or the value is not below {@code r}
     */
    public static BigInteger scalarFromBigEndian32(byte[] bytes) {
        requireLength(bytes, SCALAR_BYTES, "Scalar");
        BigInteger scalar = new BigInteger(1, bytes);
        if (scalar.compareTo(Bls12381Generators.SCALAR_FIELD_ORDER) >= 0) {
            // Never echo the value: a scalar may be secret.
            throw new IllegalArgumentException("Scalar is outside BLS12-381 Fr");
        }
        return scalar;
    }

    /**
     * Canonical 32-octet big-endian scalar encoding, {@code I2OSP(scalar, 32)}, of a value in
     * {@code [0, r)}. Never reduces. A {@link BigInteger} subclass is copied to a plain
     * {@code BigInteger} once, and only the copy is checked and encoded. Intermediate octets are
     * wiped; the caller owns the returned array.
     *
     * @throws NullPointerException     if {@code scalar} is null
     * @throws IllegalArgumentException if the value is not in {@code [0, r)}
     */
    public static byte[] scalarToBigEndian32(BigInteger scalar) {
        Objects.requireNonNull(scalar, "scalar required");
        BigInteger value = plainCopy(scalar);
        if (value.signum() < 0 || value.compareTo(Bls12381Generators.SCALAR_FIELD_ORDER) >= 0) {
            throw new IllegalArgumentException("Scalar is outside BLS12-381 Fr");
        }
        byte[] raw = value.toByteArray();
        try {
            // Below r < 2^255: at most 32 octets, or 33 with a leading zero sign octet.
            int skip = raw.length > SCALAR_BYTES ? raw.length - SCALAR_BYTES : 0;
            int length = raw.length - skip;
            byte[] out = new byte[SCALAR_BYTES];
            System.arraycopy(raw, skip, out, SCALAR_BYTES - length, length);
            return out;
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    private static BigInteger plainCopy(BigInteger x) {
        if (x.getClass() == BigInteger.class) {
            return x;
        }
        byte[] raw = x.toByteArray();
        try {
            return new BigInteger(raw);
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    public static byte[] g1ToUncompressed(G1Point point) {
        Objects.requireNonNull(point, "point required");
        byte[] out = new byte[G1_UNCOMPRESSED_BYTES];
        if (point.isInfinity()) {
            out[0] = INFINITY_FLAG;
            return out;
        }
        writeFp(out, 0, point.x().value());
        writeFp(out, FP_BYTES, point.y().value());
        return out;
    }

    public static byte[] g1ToCompressed(G1Point point) {
        Objects.requireNonNull(point, "point required");
        byte[] out = new byte[G1_COMPRESSED_BYTES];
        if (point.isInfinity()) {
            out[0] = (byte) (COMPRESSED_FLAG | INFINITY_FLAG);
            return out;
        }
        writeFp(out, 0, point.x().value());
        out[0] |= (byte) COMPRESSED_FLAG;
        if (point.y().lexicographicallyLargest()) {
            out[0] |= SORT_FLAG;
        }
        return out;
    }

    public static G1Point g1FromUncompressed(byte[] bytes) {
        return requireValid(g1FromUncompressedUnchecked(bytes));
    }

    public static G1Point g1FromCompressed(byte[] bytes) {
        return requireValid(g1FromCompressedUnchecked(bytes));
    }

    public static G1Point g1FromCompressedUnchecked(byte[] bytes) {
        requireLength(bytes, G1_COMPRESSED_BYTES, "G1 compressed");
        byte[] copy = bytes.clone();
        boolean compressed = (copy[0] & COMPRESSED_FLAG) != 0;
        boolean infinity = (copy[0] & INFINITY_FLAG) != 0;
        boolean sorted = (copy[0] & SORT_FLAG) != 0;
        copy[0] &= ~FLAG_MASK;
        if (!compressed) {
            throw new IllegalArgumentException("Invalid G1 compressed flags");
        }
        if (infinity) {
            if (sorted || !allZero(copy)) {
                throw new IllegalArgumentException("Invalid G1 compressed infinity encoding");
            }
            return G1Point.INFINITY;
        }

        var x = Fp.of(readFp(copy, 0));
        var y = x.square().mul(x).add(Fp.of(4)).sqrt()
                .orElseThrow(() -> new IllegalArgumentException("Invalid G1 compressed point"));
        if (y.lexicographicallyLargest() != sorted) {
            y = y.neg();
        }
        return new G1Point(x, y);
    }

    public static G1Point g1FromUncompressedUnchecked(byte[] bytes) {
        requireLength(bytes, G1_UNCOMPRESSED_BYTES, "G1 uncompressed");
        byte[] copy = bytes.clone();
        boolean compressed = (copy[0] & COMPRESSED_FLAG) != 0;
        boolean infinity = (copy[0] & INFINITY_FLAG) != 0;
        boolean sorted = (copy[0] & SORT_FLAG) != 0;
        copy[0] &= ~FLAG_MASK;
        if (compressed || sorted) {
            throw new IllegalArgumentException("Invalid G1 uncompressed flags");
        }
        if (infinity) {
            if (!allZero(copy)) {
                throw new IllegalArgumentException("Invalid G1 infinity encoding");
            }
            return G1Point.INFINITY;
        }
        return new G1Point(
                Fp.of(readFp(copy, 0)),
                Fp.of(readFp(copy, FP_BYTES)));
    }

    public static byte[] g2ToUncompressed(G2Point point) {
        Objects.requireNonNull(point, "point required");
        byte[] out = new byte[G2_UNCOMPRESSED_BYTES];
        if (point.isInfinity()) {
            out[0] = INFINITY_FLAG;
            return out;
        }
        writeFp(out, 0, point.x().c1().value());
        writeFp(out, FP_BYTES, point.x().c0().value());
        writeFp(out, FP_BYTES * 2, point.y().c1().value());
        writeFp(out, FP_BYTES * 3, point.y().c0().value());
        return out;
    }

    public static byte[] g2ToCompressed(G2Point point) {
        Objects.requireNonNull(point, "point required");
        byte[] out = new byte[G2_COMPRESSED_BYTES];
        if (point.isInfinity()) {
            out[0] = (byte) (COMPRESSED_FLAG | INFINITY_FLAG);
            return out;
        }
        writeFp(out, 0, point.x().c1().value());
        writeFp(out, FP_BYTES, point.x().c0().value());
        out[0] |= (byte) COMPRESSED_FLAG;
        if (point.y().lexicographicallyLargest()) {
            out[0] |= SORT_FLAG;
        }
        return out;
    }

    public static G2Point g2FromUncompressed(byte[] bytes) {
        return requireValid(g2FromUncompressedUnchecked(bytes));
    }

    public static G2Point g2FromCompressed(byte[] bytes) {
        return requireValid(g2FromCompressedUnchecked(bytes));
    }

    public static G2Point g2FromCompressedUnchecked(byte[] bytes) {
        requireLength(bytes, G2_COMPRESSED_BYTES, "G2 compressed");
        byte[] copy = bytes.clone();
        boolean compressed = (copy[0] & COMPRESSED_FLAG) != 0;
        boolean infinity = (copy[0] & INFINITY_FLAG) != 0;
        boolean sorted = (copy[0] & SORT_FLAG) != 0;
        copy[0] &= ~FLAG_MASK;
        if (!compressed) {
            throw new IllegalArgumentException("Invalid G2 compressed flags");
        }
        if (infinity) {
            if (sorted || !allZero(copy)) {
                throw new IllegalArgumentException("Invalid G2 compressed infinity encoding");
            }
            return G2Point.INFINITY;
        }

        var xc1 = Fp.of(readFp(copy, 0));
        var xc0 = Fp.of(readFp(copy, FP_BYTES));
        var x = Fp2.of(xc0, xc1);
        var twistB = Fp2.of(Fp.of(4), Fp.of(4));
        var y = x.square().mul(x).add(twistB).sqrt()
                .orElseThrow(() -> new IllegalArgumentException("Invalid G2 compressed point"));
        if (y.lexicographicallyLargest() != sorted) {
            y = y.neg();
        }
        return new G2Point(x, y);
    }

    public static G2Point g2FromUncompressedUnchecked(byte[] bytes) {
        requireLength(bytes, G2_UNCOMPRESSED_BYTES, "G2 uncompressed");
        byte[] copy = bytes.clone();
        boolean compressed = (copy[0] & COMPRESSED_FLAG) != 0;
        boolean infinity = (copy[0] & INFINITY_FLAG) != 0;
        boolean sorted = (copy[0] & SORT_FLAG) != 0;
        copy[0] &= ~FLAG_MASK;
        if (compressed || sorted) {
            throw new IllegalArgumentException("Invalid G2 uncompressed flags");
        }
        if (infinity) {
            if (!allZero(copy)) {
                throw new IllegalArgumentException("Invalid G2 infinity encoding");
            }
            return G2Point.INFINITY;
        }
        var xc1 = Fp.of(readFp(copy, 0));
        var xc0 = Fp.of(readFp(copy, FP_BYTES));
        var yc1 = Fp.of(readFp(copy, FP_BYTES * 2));
        var yc0 = Fp.of(readFp(copy, FP_BYTES * 3));
        return new G2Point(Fp2.of(xc0, xc1), Fp2.of(yc0, yc1));
    }

    public static G1Point requireValid(G1Point point) {
        Objects.requireNonNull(point, "G1 point required");
        if (!point.isOnCurve()) {
            throw new IllegalArgumentException("G1 point is not on BLS12-381");
        }
        if (!point.isInSubgroup()) {
            throw new IllegalArgumentException("G1 point is not in the prime-order subgroup");
        }
        return point;
    }

    public static G2Point requireValid(G2Point point) {
        Objects.requireNonNull(point, "G2 point required");
        if (!point.isOnCurve()) {
            throw new IllegalArgumentException("G2 point is not on BLS12-381 twist");
        }
        if (!point.isInSubgroup()) {
            throw new IllegalArgumentException("G2 point is not in the prime-order subgroup");
        }
        return point;
    }

    private static void writeFp(byte[] buf, int offset, BigInteger value) {
        byte[] bytes = fixedBigEndian(value, FP_BYTES);
        System.arraycopy(bytes, 0, buf, offset, FP_BYTES);
    }

    private static BigInteger readFp(byte[] bytes, int offset) {
        BigInteger value = new BigInteger(1, Arrays.copyOfRange(bytes, offset, offset + FP_BYTES));
        if (value.compareTo(Fp.P) >= 0) {
            throw new IllegalArgumentException("Field element is outside BLS12-381 Fp");
        }
        return value;
    }

    private static byte[] fixedBigEndian(BigInteger value, int length) {
        if (value.signum() < 0) {
            throw new IllegalArgumentException("Value must be non-negative");
        }
        byte[] raw = value.toByteArray();
        int rawStart = raw.length > 1 && raw[0] == 0 ? 1 : 0;
        int rawLen = raw.length - rawStart;
        if (rawLen > length) {
            throw new IllegalArgumentException("Value does not fit in " + length + " bytes");
        }
        byte[] out = new byte[length];
        System.arraycopy(raw, rawStart, out, length - rawLen, rawLen);
        return out;
    }

    private static void requireLength(byte[] bytes, int expected, String label) {
        Objects.requireNonNull(bytes, label + " bytes required");
        if (bytes.length != expected) {
            throw new IllegalArgumentException(label + " must be " + expected + " bytes, got " + bytes.length);
        }
    }

    private static boolean allZero(byte[] bytes) {
        int acc = 0;
        for (byte b : bytes) {
            acc |= b & 0xff;
        }
        return acc == 0;
    }

    private static void reverse(byte[] bytes) {
        for (int i = 0, j = bytes.length - 1; i < j; i++, j--) {
            byte tmp = bytes[i];
            bytes[i] = bytes[j];
            bytes[j] = tmp;
        }
    }
}
