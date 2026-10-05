package org.zeroj.circuit.lib.jubjub;

import java.util.Objects;

/**
 * Host BLAKE2b ([RFC 7693]): unkeyed, no salt or personalisation, digest length 1–64 bytes.
 * Used for the {@code elgamal-jubjub-threshold-v1} session identifier and transcript digest
 * (BLAKE2b-256). The JDK ships no BLAKE2. The in-circuit gadget is
 * {@code org.zeroj.circuit.lib.hash.Blake2b}.
 *
 * <p>A straight transcription of RFC 7693 §3. It hashes public data only. Checked against the
 * RFC's Appendix A vector, BouncyCastle and Cardano's {@code Blake2bUtil} in
 * {@code Blake2bDigestTest}.
 *
 * [RFC 7693]: https://www.rfc-editor.org/rfc/rfc7693
 */
final class Blake2bDigest {

    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    private static final byte[][] SIGMA = {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
            {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
            {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
            {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
            {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
            {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
            {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
            {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
            {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    };

    private static final int BLOCK = 128;

    private Blake2bDigest() {}

    /** BLAKE2b-256. */
    static byte[] blake2b256(byte[] input) {
        return digest(input, 32);
    }

    /** Unkeyed BLAKE2b with an {@code outLength}-byte digest, {@code 1 ≤ outLength ≤ 64}. */
    static byte[] digest(byte[] input, int outLength) {
        Objects.requireNonNull(input, "input");
        if (outLength < 1 || outLength > 64) {
            throw new IllegalArgumentException("BLAKE2b output length must be 1..64 bytes");
        }
        long[] h = IV.clone();
        h[0] ^= 0x01010000L ^ outLength; // key length 0
        long[] m = new long[16];
        long[] v = new long[16];
        int blocks = blockCount(input.length);
        // The last block starts at (blocks − 1)·128 ≤ 2^31 − 128, so offset + 127 ≤ Integer.MAX_VALUE.
        for (int b = 0; b < blocks; b++) {
            boolean last = b == blocks - 1;
            int offset = b * BLOCK;
            int length = Math.min(BLOCK, input.length - offset);
            for (int i = 0; i < 16; i++) {
                m[i] = 0;
                for (int byteIndex = 7; byteIndex >= 0; byteIndex--) {
                    int pos = offset + i * 8 + byteIndex;
                    int value = pos < offset + length ? input[pos] & 0xFF : 0;
                    m[i] = (m[i] << 8) | value;
                }
            }
            long counter = last ? input.length : (long) (b + 1) * BLOCK;
            compress(h, m, v, counter, last);
        }
        byte[] out = new byte[outLength];
        for (int i = 0; i < outLength; i++) {
            out[i] = (byte) (h[i >>> 3] >>> (8 * (i & 7)));
        }
        return out;
    }

    /**
     * The number of 128-byte blocks for {@code length} input bytes: {@code ⌈length / 128⌉}, and
     * one for the empty input (RFC 7693 §3.3). Widened, so it is exact for every array length.
     */
    static int blockCount(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("length must be non-negative");
        }
        return length == 0 ? 1 : (int) ((length + (long) BLOCK - 1) / BLOCK);
    }

    private static void compress(long[] h, long[] m, long[] v, long counter, boolean last) {
        System.arraycopy(h, 0, v, 0, 8);
        System.arraycopy(IV, 0, v, 8, 8);
        v[12] ^= counter; // the high 64 bits of the 128-bit counter stay zero (inputs < 2^63 bytes)
        if (last) {
            v[14] = ~v[14];
        }
        for (int round = 0; round < 12; round++) {
            byte[] s = SIGMA[round % 10];
            mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void mix(long[] v, int a, int b, int c, int d, long x, long y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Long.rotateRight(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Long.rotateRight(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Long.rotateRight(v[b] ^ v[c], 63);
    }
}
