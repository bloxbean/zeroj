package org.zeroj.bls12381.bulletproofs;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * The byte codecs of {@code draft-irtf-cfrg-fiat-shamir-03} §2.1, §4.2 and §6 that this protocol
 * uses, in their general form (any modulus), so that the draft's Appendix B.1 vectors exercise the
 * same code. Spec {@code bulletproof-range-bls12-381-g1-v1} §3, §5.2.
 *
 * <p>The deserializers return a failure as {@code null} rather than throwing: in the draft a
 * deserialization failure is a verification failure, and callers map it to their own error class.
 */
final class FsCodec {

    private FsCodec() {
    }

    /** {@code Ns}: the smallest integer with {@code 256^Ns ≥ M} (§6.1.3). */
    static int byteLength(BigInteger modulus) {
        requirePositive(modulus);
        // 256^Ns ≥ M ⟺ 8·Ns ≥ bitLength(M − 1).
        return (modulus.subtract(BigInteger.ONE).bitLength() + 7) / 8;
    }

    /** {@code LE(x, w)}: the {@code w}-octet little-endian encoding of {@code 0 ≤ x < 256^w} (§2.1). */
    static byte[] le(BigInteger x, int width) {
        Objects.requireNonNull(x, "x");
        if (x.signum() < 0 || x.bitLength() > 8 * width) {
            throw new IllegalArgumentException("LE(x, w) is undefined for this value");
        }
        byte[] out = new byte[width];
        byte[] be = x.toByteArray();
        try {
            for (int i = 0; i < width && i < be.length; i++) {
                out[i] = be[be.length - 1 - i];
            }
        } finally {
            Arrays.fill(be, (byte) 0);
        }
        return out;
    }

    /** {@code LE2IP(buf)}: the non-negative integer whose little-endian encoding is {@code buf} (§2.1). */
    static BigInteger le2ip(byte[] buf) {
        Objects.requireNonNull(buf, "buf");
        byte[] be = new byte[buf.length];
        for (int i = 0; i < buf.length; i++) {
            be[i] = buf[buf.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    /** {@code SerializeVarLenString(s) = LE(len(s), 4) ‖ s} (§6.1.1). */
    static byte[] serializeVarLenString(byte[] s) {
        Objects.requireNonNull(s, "s");
        byte[] out = new byte[4 + s.length];
        System.arraycopy(le(BigInteger.valueOf(s.length), 4), 0, out, 0, 4);
        System.arraycopy(s, 0, out, 4, s.length);
        return out;
    }

    /** {@code SerializeUint(x, M) = LE(x, Ns)}, for {@code 0 ≤ x < M} (§6.1.3). */
    static byte[] serializeUint(BigInteger x, BigInteger modulus) {
        Objects.requireNonNull(x, "x");
        requirePositive(modulus);
        if (x.signum() < 0 || x.compareTo(modulus) >= 0) {
            throw new IllegalArgumentException("SerializeUint requires 0 ≤ x < M");
        }
        return le(x, byteLength(modulus));
    }

    /**
     * {@code SerializeField(a, p, 1)} under a pinned big-endian serialization: {@code I2OSP(a, Ns)}
     * for {@code 0 ≤ a < p} (§6.1.4, sigma-03 §8.2.2).
     */
    static byte[] serializeFieldBigEndian(BigInteger a, BigInteger p) {
        byte[] le = serializeUint(a, p);
        byte[] be = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            be[i] = le[le.length - 1 - i];
        }
        return be;
    }

    /** {@code DecodeUint(buf, M) = LE2IP(buf) mod M}, for {@code len(buf) = Ns + 16} (§4.2.2). */
    static BigInteger decodeUint(byte[] buf, BigInteger modulus) {
        Objects.requireNonNull(buf, "buf");
        requirePositive(modulus);
        if (buf.length != byteLength(modulus) + 16) {
            throw new IllegalArgumentException("DecodeUint takes Ns + 16 octets");
        }
        return le2ip(buf).mod(modulus);
    }

    /**
     * {@code DeserializeUint(input, M)} (§6.2.3) on the whole of {@code input}: the integer, or
     * {@code null} if {@code input} is shorter than {@code Ns} or the value is at least {@code M}.
     * Trailing octets beyond {@code Ns} are the caller's remainder and are ignored here.
     */
    static BigInteger deserializeUint(byte[] input, BigInteger modulus) {
        Objects.requireNonNull(input, "input");
        int ns = byteLength(modulus);
        if (input.length < ns) {
            return null;
        }
        BigInteger x = le2ip(Arrays.copyOf(input, ns));
        return x.compareTo(modulus) >= 0 ? null : x;
    }

    /**
     * {@code DeserializeVarLenString(input)} (§6.2.1): the string, or {@code null} if fewer than 4
     * octets remain or fewer than the declared length follow them.
     */
    static byte[] deserializeVarLenString(byte[] input) {
        Objects.requireNonNull(input, "input");
        if (input.length < 4) {
            return null;
        }
        long n = le2ip(Arrays.copyOf(input, 4)).longValueExact();
        if (input.length - 4L < n) {
            return null;
        }
        return Arrays.copyOfRange(input, 4, 4 + (int) n);
    }

    private static void requirePositive(BigInteger modulus) {
        Objects.requireNonNull(modulus, "modulus");
        if (modulus.signum() <= 0) {
            throw new IllegalArgumentException("modulus must be positive");
        }
    }
}
