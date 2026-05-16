package com.bloxbean.cardano.zeroj.bls12381;

import java.math.BigInteger;
import com.bloxbean.cardano.zeroj.bls12381.ec.G1Point;
import com.bloxbean.cardano.zeroj.bls12381.ec.G2Point;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Hash helpers shared by BLS12-381 providers.
 */
public final class Bls12381Hash {
    private static final int SHA256_BYTES = 32;
    private static final int SHA256_BLOCK_BYTES = 64;
    private static final int SHAKE256_RATE_BYTES = 136;
    private static final int SHAKE256_OVERSIZE_DST_BYTES = 32;
    private static final int SCALAR_HASH_BYTES = 48;
    private static final byte[] OVERSIZE_DST_PREFIX = "H2C-OVERSIZE-DST-".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int[] KECCAK_ROTATION = {
            0, 1, 62, 28, 27,
            36, 44, 6, 55, 20,
            3, 10, 43, 25, 39,
            41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
    };
    private static final long[] KECCAK_ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private Bls12381Hash() {}

    public static BigInteger hashToScalar(byte[] message, byte[] dst) {
        byte[] uniform = expandMessageXmdSha256(message, dst, SCALAR_HASH_BYTES);
        return new BigInteger(1, uniform).mod(Bls12381Generators.SCALAR_FIELD_ORDER);
    }

    public static BigInteger hashToScalarXofShake256(byte[] message, byte[] dst) {
        byte[] uniform = expandMessageXofShake256(message, dst, SCALAR_HASH_BYTES);
        return new BigInteger(1, uniform).mod(Bls12381Generators.SCALAR_FIELD_ORDER);
    }

    public static G1Point hashToG1(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.hashToG1(message, dst);
    }

    public static G1Point encodeToG1(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.encodeToG1(message, dst);
    }

    public static G1Point hashToG1XofShake256(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.hashToG1XofShake256(message, dst);
    }

    public static G1Point encodeToG1XofShake256(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.encodeToG1XofShake256(message, dst);
    }

    public static G2Point hashToG2(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.hashToG2(message, dst);
    }

    public static G2Point encodeToG2(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.encodeToG2(message, dst);
    }

    public static G2Point hashToG2XofShake256(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.hashToG2XofShake256(message, dst);
    }

    public static G2Point encodeToG2XofShake256(byte[] message, byte[] dst) {
        return Bls12381HashToCurve.encodeToG2XofShake256(message, dst);
    }

    public static byte[] expandMessageXmdSha256(byte[] message, byte[] dst, int lenInBytes) {
        Objects.requireNonNull(message, "message required");
        Objects.requireNonNull(dst, "dst required");
        if (lenInBytes < 0 || lenInBytes > 255 * SHA256_BYTES) {
            throw new IllegalArgumentException("Invalid expand_message_xmd length: " + lenInBytes);
        }
        if (lenInBytes == 0) {
            return new byte[0];
        }
        byte[] effectiveDst = dst;
        if (effectiveDst.length > 255) {
            effectiveDst = sha256(concat(OVERSIZE_DST_PREFIX, effectiveDst));
        }

        int ell = (lenInBytes + SHA256_BYTES - 1) / SHA256_BYTES;
        byte[] dstPrime = concat(effectiveDst, new byte[]{(byte) effectiveDst.length});
        byte[] zPad = new byte[SHA256_BLOCK_BYTES];
        byte[] lenBytes = new byte[]{(byte) (lenInBytes >>> 8), (byte) lenInBytes};

        byte[] b0 = sha256(concat(zPad, message, lenBytes, new byte[]{0}, dstPrime));
        byte[] bi = sha256(concat(b0, new byte[]{1}, dstPrime));
        byte[] uniform = new byte[ell * SHA256_BYTES];
        System.arraycopy(bi, 0, uniform, 0, SHA256_BYTES);

        for (int i = 2; i <= ell; i++) {
            bi = sha256(concat(xor(b0, bi), new byte[]{(byte) i}, dstPrime));
            System.arraycopy(bi, 0, uniform, (i - 1) * SHA256_BYTES, SHA256_BYTES);
        }
        return Arrays.copyOf(uniform, lenInBytes);
    }

    public static byte[] expandMessageXofShake256(byte[] message, byte[] dst, int lenInBytes) {
        Objects.requireNonNull(message, "message required");
        Objects.requireNonNull(dst, "dst required");
        if (lenInBytes < 0 || lenInBytes > 0xffff) {
            throw new IllegalArgumentException("Invalid expand_message_xof length: " + lenInBytes);
        }
        if (lenInBytes == 0) {
            return new byte[0];
        }
        byte[] effectiveDst = dst;
        if (effectiveDst.length > 255) {
            effectiveDst = shake256(concat(OVERSIZE_DST_PREFIX, effectiveDst), SHAKE256_OVERSIZE_DST_BYTES);
        }

        byte[] dstPrime = concat(effectiveDst, new byte[]{(byte) effectiveDst.length});
        byte[] lenBytes = new byte[]{(byte) (lenInBytes >>> 8), (byte) lenInBytes};
        return shake256(concat(message, lenBytes, dstPrime), lenInBytes);
    }

    static BigInteger[] hashToFp(byte[] message, byte[] dst, int count) {
        byte[] uniform = expandMessageXmdSha256(message, dst, count * 64);
        BigInteger[] out = new BigInteger[count];
        for (int i = 0; i < count; i++) {
            out[i] = new BigInteger(1, Arrays.copyOfRange(uniform, i * 64, (i + 1) * 64))
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.Fp.P);
        }
        return out;
    }

    static BigInteger[] hashToFpXofShake256(byte[] message, byte[] dst, int count) {
        byte[] uniform = expandMessageXofShake256(message, dst, count * 64);
        BigInteger[] out = new BigInteger[count];
        for (int i = 0; i < count; i++) {
            out[i] = new BigInteger(1, Arrays.copyOfRange(uniform, i * 64, (i + 1) * 64))
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.Fp.P);
        }
        return out;
    }

    static BigInteger[][] hashToFp2(byte[] message, byte[] dst, int count) {
        byte[] uniform = expandMessageXmdSha256(message, dst, count * 2 * 64);
        BigInteger[][] out = new BigInteger[count][2];
        for (int i = 0; i < count; i++) {
            int offset = i * 128;
            out[i][0] = new BigInteger(1, Arrays.copyOfRange(uniform, offset, offset + 64))
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.Fp.P);
            out[i][1] = new BigInteger(1, Arrays.copyOfRange(uniform, offset + 64, offset + 128))
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.Fp.P);
        }
        return out;
    }

    static BigInteger[][] hashToFp2XofShake256(byte[] message, byte[] dst, int count) {
        byte[] uniform = expandMessageXofShake256(message, dst, count * 2 * 64);
        BigInteger[][] out = new BigInteger[count][2];
        for (int i = 0; i < count; i++) {
            int offset = i * 128;
            out[i][0] = new BigInteger(1, Arrays.copyOfRange(uniform, offset, offset + 64))
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.Fp.P);
            out[i][1] = new BigInteger(1, Arrays.copyOfRange(uniform, offset + 64, offset + 128))
                    .mod(com.bloxbean.cardano.zeroj.bls12381.field.Fp.P);
        }
        return out;
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    private static byte[] shake256(byte[] input, int lenInBytes) {
        if (lenInBytes < 0) {
            throw new IllegalArgumentException("Invalid SHAKE256 output length: " + lenInBytes);
        }
        long[] state = new long[25];
        int offset = 0;
        while (input.length - offset >= SHAKE256_RATE_BYTES) {
            absorbBlock(state, input, offset);
            keccakF1600(state);
            offset += SHAKE256_RATE_BYTES;
        }

        byte[] finalBlock = new byte[SHAKE256_RATE_BYTES];
        int remaining = input.length - offset;
        System.arraycopy(input, offset, finalBlock, 0, remaining);
        finalBlock[remaining] ^= 0x1f;
        finalBlock[SHAKE256_RATE_BYTES - 1] ^= (byte) 0x80;
        absorbBlock(state, finalBlock, 0);
        keccakF1600(state);

        byte[] out = new byte[lenInBytes];
        int outOffset = 0;
        while (outOffset < lenInBytes) {
            int blockLen = Math.min(SHAKE256_RATE_BYTES, lenInBytes - outOffset);
            squeezeBlock(state, out, outOffset, blockLen);
            outOffset += blockLen;
            if (outOffset < lenInBytes) {
                keccakF1600(state);
            }
        }
        return out;
    }

    private static void absorbBlock(long[] state, byte[] block, int offset) {
        for (int i = 0; i < SHAKE256_RATE_BYTES; i++) {
            state[i >>> 3] ^= (block[offset + i] & 0xffL) << (8 * (i & 7));
        }
    }

    private static void squeezeBlock(long[] state, byte[] out, int offset, int len) {
        for (int i = 0; i < len; i++) {
            out[offset + i] = (byte) (state[i >>> 3] >>> (8 * (i & 7)));
        }
    }

    private static void keccakF1600(long[] state) {
        long[] b = new long[25];
        long[] c = new long[5];
        long[] d = new long[5];
        for (long roundConstant : KECCAK_ROUND_CONSTANTS) {
            for (int x = 0; x < 5; x++) {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            for (int x = 0; x < 5; x++) {
                d[x] = c[(x + 4) % 5] ^ Long.rotateLeft(c[(x + 1) % 5], 1);
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    state[x + 5 * y] ^= d[x];
                }
            }

            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    b[y + 5 * ((2 * x + 3 * y) % 5)] =
                            Long.rotateLeft(state[x + 5 * y], KECCAK_ROTATION[x + 5 * y]);
                }
            }
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    state[x + 5 * y] = b[x + 5 * y]
                            ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
                }
            }
            state[0] ^= roundConstant;
        }
    }

    private static byte[] xor(byte[] left, byte[] right) {
        byte[] out = new byte[left.length];
        for (int i = 0; i < left.length; i++) {
            out[i] = (byte) (left[i] ^ right[i]);
        }
        return out;
    }

    private static byte[] concat(byte[]... chunks) {
        int len = 0;
        for (byte[] chunk : chunks) {
            len += chunk.length;
        }
        byte[] out = new byte[len];
        int offset = 0;
        for (byte[] chunk : chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.length);
            offset += chunk.length;
        }
        return out;
    }
}
