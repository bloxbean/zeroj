package com.bloxbean.cardano.zeroj.circuit.lib.hash;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * In-circuit BLAKE2b (RFC 7693) gadget — unkeyed, parameterized digest length.
 *
 * <p>Supports arbitrary output length in {@code [1, 64]} bytes; the two that matter for
 * Cardano are <b>blake2b-224</b> (28 bytes — payment/stake key hash) and <b>blake2b-256</b>
 * (32 bytes). The digest length {@code nn} enters only via the parameter block
 * ({@code h[0] ^= 0x01010000 ^ (kk<<8) ^ nn}, with key length {@code kk = 0}) and the final
 * output truncation, so all lengths share one compression core.</p>
 *
 * <h2>Data model</h2>
 * BLAKE2b is <b>little-endian</b> (unlike SHA-512). A 64-bit word is an LSB-first
 * {@code Variable[64]} ({@code bit[i]} weight {@code 2^i}); message/output bytes pack
 * little-endian into words. Rotations here are ROTR (free index re-labelling); additions are
 * mod-2^64 via a single carry decomposition.
 *
 * <p>Field-agnostic like {@link Sha512}. Message bytes are range-checked to 8 bits when packed.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7693">RFC 7693</a>
 */
public final class Blake2b {

    private Blake2b() {}

    private static final int WORD_BITS = 64;
    private static final int BLOCK_BYTES = 128;

    /** BLAKE2b IV = first 64 bits of the fractional parts of sqrt of the first 8 primes. */
    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    /** Message-word permutation SIGMA (RFC 7693 §2.7), 12 rounds × 16 indices. */
    private static final int[][] SIGMA = {
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
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    /** blake2b-224 (Cardano key hash): 28-byte digest as field-element bytes in [0,255]. */
    public static Variable[] hash224(CircuitAPI api, Variable[] messageBytes) {
        return hash(api, messageBytes, 28);
    }

    /** blake2b-256: 32-byte digest as field-element bytes in [0,255]. */
    public static Variable[] hash256(CircuitAPI api, Variable[] messageBytes) {
        return hash(api, messageBytes, 32);
    }

    /**
     * Unkeyed BLAKE2b with {@code outLenBytes} in [1,64]. Message bytes are field elements in
     * [0,255] (range-checked). Returns {@code outLenBytes} field-element bytes.
     */
    public static Variable[] hash(CircuitAPI api, Variable[] messageBytes, int outLenBytes) {
        if (outLenBytes < 1 || outLenBytes > 64)
            throw new IllegalArgumentException("outLenBytes must be in [1,64], got " + outLenBytes);
        int msgLen = messageBytes.length;

        // Initialize state h[0..7] = IV, with the parameter block folded into h[0].
        // Parameter block low word p[0] = 0x01010000 ^ (kk << 8) ^ nn, kk = 0 (unkeyed).
        long param0 = 0x01010000L ^ ((long) outLenBytes);
        Variable[][] h = new Variable[8][];
        h[0] = constWord(api, IV[0] ^ param0);
        for (int i = 1; i < 8; i++) h[i] = constWord(api, IV[i]);

        // Pre-decompose every message byte to 8 LSB-first bits (range-checks each to [0,255]).
        Variable zero = api.constant(0);
        Variable[][] msgBits = new Variable[msgLen][];
        for (int i = 0; i < msgLen; i++) msgBits[i] = api.toBinary(messageBytes[i], 8);

        int numBlocks = Math.max(1, (msgLen + BLOCK_BYTES - 1) / BLOCK_BYTES);
        for (int blk = 0; blk < numBlocks; blk++) {
            // Build the 16 little-endian message words for this block (zero-padded past msgLen).
            Variable[][] m = new Variable[16][];
            for (int w = 0; w < 16; w++) {
                Variable[] word = new Variable[WORD_BITS];
                for (int b = 0; b < 8; b++) {
                    int byteIdx = blk * BLOCK_BYTES + w * 8 + b;
                    for (int bit = 0; bit < 8; bit++) {
                        Variable v = (byteIdx < msgLen) ? msgBits[byteIdx][bit] : zero;
                        word[b * 8 + bit] = v; // LE: byte b occupies bits [8b, 8b+7]
                    }
                }
                m[w] = word;
            }

            long counter = (blk < numBlocks - 1) ? (long) (blk + 1) * BLOCK_BYTES : (long) msgLen;
            boolean last = (blk == numBlocks - 1);
            h = compress(api, h, m, counter, last);
        }

        // Serialize h[0..7] little-endian, take the first outLenBytes bytes.
        Variable[] out = new Variable[outLenBytes];
        for (int i = 0; i < outLenBytes; i++) {
            int w = i / 8, byteInWord = i % 8;
            Variable[] le = new Variable[8];
            for (int bit = 0; bit < 8; bit++) le[bit] = h[w][byteInWord * 8 + bit];
            out[i] = api.fromBinary(le);
        }
        return out;
    }

    // ---------------------------------------------------------------------
    // Compression F
    // ---------------------------------------------------------------------

    private static Variable[][] compress(CircuitAPI api, Variable[][] h, Variable[][] m,
                                         long counter, boolean last) {
        Variable[][] v = new Variable[16][];
        for (int i = 0; i < 8; i++) v[i] = h[i];
        for (int i = 0; i < 8; i++) v[8 + i] = constWord(api, IV[i]);

        // v[12] ^= t_lo, v[13] ^= t_hi (message length fits a long => t_hi = 0).
        v[12] = xorConst(api, v[12], counter);
        v[13] = xorConst(api, v[13], 0L);
        if (last) v[14] = xorConst(api, v[14], 0xffffffffffffffffL); // invert all bits

        for (int r = 0; r < 12; r++) {
            int[] s = SIGMA[r];
            mix(api, v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            mix(api, v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            mix(api, v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            mix(api, v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            mix(api, v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            mix(api, v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            mix(api, v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            mix(api, v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        Variable[][] out = new Variable[8][];
        for (int i = 0; i < 8; i++) out[i] = xor(api, xor(api, h[i], v[i]), v[i + 8]);
        return out;
    }

    /** BLAKE2b G mixing function (RFC 7693 §3.1) on state words a,b,c,d with inputs x,y. */
    private static void mix(CircuitAPI api, Variable[][] v, int a, int b, int c, int d,
                            Variable[] x, Variable[] y) {
        v[a] = addMod64(api, v[a], v[b], x);
        v[d] = rotr(xor(api, v[d], v[a]), 32);
        v[c] = addMod64(api, v[c], v[d]);
        v[b] = rotr(xor(api, v[b], v[c]), 24);
        v[a] = addMod64(api, v[a], v[b], y);
        v[d] = rotr(xor(api, v[d], v[a]), 16);
        v[c] = addMod64(api, v[c], v[d]);
        v[b] = rotr(xor(api, v[b], v[c]), 63);
    }

    // ---------------------------------------------------------------------
    // 64-bit word helpers (LSB-first)
    // ---------------------------------------------------------------------

    /** Circular right-rotate: result bit k = old bit (k+n) mod 64. */
    private static Variable[] rotr(Variable[] w, int n) {
        n %= WORD_BITS;
        Variable[] r = new Variable[WORD_BITS];
        for (int k = 0; k < WORD_BITS; k++) r[k] = w[(k + n) % WORD_BITS];
        return r;
    }

    private static Variable[] xor(CircuitAPI api, Variable[] a, Variable[] b) {
        Variable[] r = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) r[i] = api.xor(a[i], b[i]);
        return r;
    }

    /** XOR a word with a compile-time constant (flips bits where the constant is 1). */
    private static Variable[] xorConst(CircuitAPI api, Variable[] w, long c) {
        Variable[] r = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++)
            r[i] = (((c >>> i) & 1L) == 1L) ? api.not(w[i]) : w[i];
        return r;
    }

    /** Addition of 2–3 words mod 2^64: sum as field elements, then split value/carry. */
    private static Variable[] addMod64(CircuitAPI api, Variable[]... words) {
        Variable sum = api.constant(0);
        for (Variable[] w : words) sum = api.add(sum, api.fromBinary(w));
        int extra = 0;
        while ((1 << extra) < words.length) extra++;
        Variable[] full = api.toBinary(sum, WORD_BITS + extra);
        Variable[] low = new Variable[WORD_BITS];
        System.arraycopy(full, 0, low, 0, WORD_BITS);
        return low;
    }

    private static Variable[] constWord(CircuitAPI api, long value) {
        Variable[] w = new Variable[WORD_BITS];
        Variable zero = api.constant(0);
        Variable one = api.constant(1);
        for (int i = 0; i < WORD_BITS; i++) w[i] = (((value >>> i) & 1L) == 1L) ? one : zero;
        return w;
    }
}
