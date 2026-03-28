package com.bloxbean.cardano.zeroj.verifier.plonk;

/**
 * Minimal Keccak-256 implementation for Fiat-Shamir transcript compatibility with snarkjs.
 *
 * <p>Keccak-256 differs from SHA3-256 in the padding byte (0x01 vs 0x06).
 * snarkjs uses Keccak-256 (Ethereum-style), not NIST SHA3-256.</p>
 */
final class Keccak256 {

    private Keccak256() {}

    private static final int RATE = 136; // (1600 - 2*256) / 8

    static byte[] hash(byte[] input) {
        long[] state = new long[25];

        int offset = 0;
        // Absorb full blocks
        while (offset + RATE <= input.length) {
            absorb(state, input, offset, RATE);
            keccakF(state);
            offset += RATE;
        }

        // Pad and absorb last block
        byte[] lastBlock = new byte[RATE];
        int remaining = input.length - offset;
        System.arraycopy(input, offset, lastBlock, 0, remaining);
        lastBlock[remaining] = 0x01; // Keccak padding (NOT SHA3's 0x06)
        lastBlock[RATE - 1] |= (byte) 0x80;
        absorb(state, lastBlock, 0, RATE);
        keccakF(state);

        // Squeeze 32 bytes
        byte[] output = new byte[32];
        for (int i = 0; i < 4; i++) {
            long v = state[i];
            for (int j = 0; j < 8; j++) {
                output[i * 8 + j] = (byte) (v >>> (j * 8));
            }
        }
        return output;
    }

    private static void absorb(long[] state, byte[] data, int offset, int len) {
        for (int i = 0; i < len / 8; i++) {
            state[i] ^= readLE64(data, offset + i * 8);
        }
    }

    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
            0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static void keccakF(long[] a) {
        for (int round = 0; round < 24; round++) {
            // θ
            long c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
            long c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
            long c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
            long c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
            long c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];

            long d0 = c4 ^ Long.rotateLeft(c1, 1);
            long d1 = c0 ^ Long.rotateLeft(c2, 1);
            long d2 = c1 ^ Long.rotateLeft(c3, 1);
            long d3 = c2 ^ Long.rotateLeft(c4, 1);
            long d4 = c3 ^ Long.rotateLeft(c0, 1);

            a[0] ^= d0; a[5] ^= d0; a[10] ^= d0; a[15] ^= d0; a[20] ^= d0;
            a[1] ^= d1; a[6] ^= d1; a[11] ^= d1; a[16] ^= d1; a[21] ^= d1;
            a[2] ^= d2; a[7] ^= d2; a[12] ^= d2; a[17] ^= d2; a[22] ^= d2;
            a[3] ^= d3; a[8] ^= d3; a[13] ^= d3; a[18] ^= d3; a[23] ^= d3;
            a[4] ^= d4; a[9] ^= d4; a[14] ^= d4; a[19] ^= d4; a[24] ^= d4;

            // ρ and π combined
            long t = a[1];
            long tmp;
            tmp = a[10]; a[10] = Long.rotateLeft(t,  1); t = tmp;
            tmp = a[ 7]; a[ 7] = Long.rotateLeft(t,  3); t = tmp;
            tmp = a[11]; a[11] = Long.rotateLeft(t,  6); t = tmp;
            tmp = a[17]; a[17] = Long.rotateLeft(t, 10); t = tmp;
            tmp = a[18]; a[18] = Long.rotateLeft(t, 15); t = tmp;
            tmp = a[ 3]; a[ 3] = Long.rotateLeft(t, 21); t = tmp;
            tmp = a[ 5]; a[ 5] = Long.rotateLeft(t, 28); t = tmp;
            tmp = a[16]; a[16] = Long.rotateLeft(t, 36); t = tmp;
            tmp = a[ 8]; a[ 8] = Long.rotateLeft(t, 45); t = tmp;
            tmp = a[21]; a[21] = Long.rotateLeft(t, 55); t = tmp;
            tmp = a[24]; a[24] = Long.rotateLeft(t,  2); t = tmp;
            tmp = a[ 4]; a[ 4] = Long.rotateLeft(t, 14); t = tmp;
            tmp = a[15]; a[15] = Long.rotateLeft(t, 27); t = tmp;
            tmp = a[23]; a[23] = Long.rotateLeft(t, 41); t = tmp;
            tmp = a[19]; a[19] = Long.rotateLeft(t, 56); t = tmp;
            tmp = a[13]; a[13] = Long.rotateLeft(t,  8); t = tmp;
            tmp = a[12]; a[12] = Long.rotateLeft(t, 25); t = tmp;
            tmp = a[ 2]; a[ 2] = Long.rotateLeft(t, 43); t = tmp;
            tmp = a[20]; a[20] = Long.rotateLeft(t, 62); t = tmp;
            tmp = a[14]; a[14] = Long.rotateLeft(t, 18); t = tmp;
            tmp = a[22]; a[22] = Long.rotateLeft(t, 39); t = tmp;
            tmp = a[ 9]; a[ 9] = Long.rotateLeft(t, 61); t = tmp;
            tmp = a[ 6]; a[ 6] = Long.rotateLeft(t, 20); t = tmp;
            a[1] = Long.rotateLeft(t, 44);

            // χ
            for (int y = 0; y < 25; y += 5) {
                long a0 = a[y], a1 = a[y + 1], a2 = a[y + 2], a3 = a[y + 3], a4 = a[y + 4];
                a[y]     = a0 ^ (~a1 & a2);
                a[y + 1] = a1 ^ (~a2 & a3);
                a[y + 2] = a2 ^ (~a3 & a4);
                a[y + 3] = a3 ^ (~a4 & a0);
                a[y + 4] = a4 ^ (~a0 & a1);
            }

            // ι
            a[0] ^= RC[round];
        }
    }

    private static long readLE64(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off+1] & 0xFFL) << 8) | ((b[off+2] & 0xFFL) << 16)
                | ((b[off+3] & 0xFFL) << 24) | ((b[off+4] & 0xFFL) << 32) | ((b[off+5] & 0xFFL) << 40)
                | ((b[off+6] & 0xFFL) << 48) | ((b[off+7] & 0xFFL) << 56);
    }
}
