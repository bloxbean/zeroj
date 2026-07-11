package com.bloxbean.cardano.zeroj.tools.zkey;

import java.math.BigInteger;

/**
 * Bit-exact port of ffjavascript's {@code ChaCha} PRNG (ADR-0031 M5) — the deterministic stream
 * snarkjs derives ceremony challenge points from ({@code hashToG2}). Not a general-purpose ChaCha:
 * it reproduces ffjavascript's exact state layout (4 magic words, 8 seed words, 4 zero words with
 * word 12 as the block counter), 10 double-rounds, and sequential word emission.
 */
final class ChaChaRng {

    private final int[] state = new int[16];
    private final int[] buff = new int[16];
    private int idx = 16;

    /** @param seed 8 words (ffjavascript: 8 big-endian u32 from the first 32 transcript bytes) */
    ChaChaRng(int[] seed) {
        state[0] = 0x61707865;
        state[1] = 0x3320646E;
        state[2] = 0x79622D32;
        state[3] = 0x6B206574;
        System.arraycopy(seed, 0, state, 4, 8);
        // words 12..15 start at zero; word 12 is the counter
    }

    int nextU32() {
        if (idx == 16) update();
        return buff[idx++];
    }

    /** ffjavascript: {@code nextU32()·2³² + nextU32()} — FIRST word is the HIGH half. */
    BigInteger nextU64() {
        long hi = Integer.toUnsignedLong(nextU32());
        long lo = Integer.toUnsignedLong(nextU32());
        return BigInteger.valueOf(hi).shiftLeft(32).or(BigInteger.valueOf(lo));
    }

    boolean nextBool() {
        return (nextU32() & 1) == 1;
    }

    private void update() {
        System.arraycopy(state, 0, buff, 0, 16);
        for (int i = 0; i < 10; i++) doubleRound(buff);
        for (int i = 0; i < 16; i++) buff[i] += state[i];
        idx = 0;
        state[12]++;
        if (state[12] != 0) return;
        state[13]++;
        if (state[13] != 0) return;
        state[14]++;
        if (state[14] != 0) return;
        state[15]++;
    }

    private static void doubleRound(int[] st) {
        quarterRound(st, 0, 4, 8, 12);
        quarterRound(st, 1, 5, 9, 13);
        quarterRound(st, 2, 6, 10, 14);
        quarterRound(st, 3, 7, 11, 15);
        quarterRound(st, 0, 5, 10, 15);
        quarterRound(st, 1, 6, 11, 12);
        quarterRound(st, 2, 7, 8, 13);
        quarterRound(st, 3, 4, 9, 14);
    }

    private static void quarterRound(int[] st, int a, int b, int c, int d) {
        st[a] += st[b];
        st[d] ^= st[a];
        st[d] = Integer.rotateLeft(st[d], 16);
        st[c] += st[d];
        st[b] ^= st[c];
        st[b] = Integer.rotateLeft(st[b], 12);
        st[a] += st[b];
        st[d] ^= st[a];
        st[d] = Integer.rotateLeft(st[d], 8);
        st[c] += st[d];
        st[b] ^= st[c];
        st[b] = Integer.rotateLeft(st[b], 7);
    }
}
