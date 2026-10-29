package org.zeroj.blst.ffm;

import org.zeroj.bls12381.Bls12381Generators;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * Input checks and scalar encoding shared by {@link BlstG1Msm} and {@link BlstG2Msm}
 * (ADR-0062 D4, I5): no public MSM entry point truncates a scalar or lets a compressed or
 * sort-flagged encoding reach {@code blst_p*_deserialize}.
 */
final class BlstMsmInputs {

    private BlstMsmInputs() {}

    static final BigInteger R = Bls12381Generators.SCALAR_FIELD_ORDER;

    /** {@code r} as 32 little-endian bytes, for the canonical-scalar comparison. */
    private static final byte[] R_LE = new byte[32];

    static {
        byte[] be = R.toByteArray(); // r < 2^255: at most 32 bytes, no sign byte
        for (int i = 0; i < be.length; i++) R_LE[i] = be[be.length - 1 - i];
    }

    /**
     * Writes {@code v mod r} as exactly 32 little-endian bytes into {@code dst}. Reducing first
     * (rather than keeping the low 32 bytes of {@code toByteArray()}) matches the
     * {@code Bls12381Provider} scalar semantics for negative and oversized scalars.
     */
    static void scalarLe(BigInteger v, byte[] dst) {
        BigInteger reduced = Objects.requireNonNull(v, "scalar required").mod(R);
        byte[] be = reduced.toByteArray(); // reduced < r < 2^255: at most 32 bytes
        Arrays.fill(dst, 0, 32, (byte) 0);
        for (int i = 0; i < be.length; i++) dst[i] = be[be.length - 1 - i];
    }

    /** Rejects a 32-byte little-endian scalar that is not canonical ({@code >= r}). */
    static void requireCanonicalScalar(byte[] le32, int index) {
        for (int i = 31; i >= 0; i--) {
            int a = le32[i] & 0xff;
            int b = R_LE[i] & 0xff;
            if (a < b) return;
            if (a > b) break;
        }
        throw new IllegalArgumentException("Scalar " + index + " is not canonical (must be < r)");
    }

    /**
     * Rejects an encoding with the compression ({@code 0x80}) or sort ({@code 0x20}) flag set. The
     * MSM consumes only uncompressed encodings; without this check blst would read a compressed
     * prefix and ignore the rest of the buffer.
     */
    static void requireUncompressedFlags(byte[] encoding, int index) {
        if ((encoding[0] & 0xA0) != 0) {
            throw new IllegalArgumentException("Point " + index
                    + " has the compression or sort flag set; an uncompressed encoding is required");
        }
    }

    static void requireLength(byte[] encoding, int expected, int index) {
        if (Objects.requireNonNull(encoding, "point encoding required").length != expected) {
            throw new IllegalArgumentException("Point " + index + " must be " + expected + " bytes, got "
                    + encoding.length);
        }
    }

    static void requireSameLength(int points, BigInteger[] scalars) {
        Objects.requireNonNull(scalars, "scalars required");
        if (points != scalars.length) {
            throw new IllegalArgumentException("MSM needs one scalar per point: " + points + " points, "
                    + scalars.length + " scalars");
        }
    }
}
