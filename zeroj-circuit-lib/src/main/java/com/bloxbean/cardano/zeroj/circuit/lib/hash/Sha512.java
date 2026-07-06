package com.bloxbean.cardano.zeroj.circuit.lib.hash;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * In-circuit SHA-512 (FIPS 180-4) gadget over an arbitrary scalar field.
 *
 * <p>This gadget is <b>field-agnostic</b>: all intermediate values fit in ~67 bits, which
 * is representable in both the BN254 and BLS12-381 scalar fields, so it does <i>not</i> call
 * {@link CircuitAPI#requireField}. For ZeroJ's Cardano roadmap it is compiled for BLS12-381,
 * but the BN254 default field is used in unit tests for parity with the rest of the stdlib.
 *
 * <h2>Data model</h2>
 * A 64-bit SHA word is represented internally as a {@code Variable[64]} of bits in
 * <b>LSB-first</b> order — {@code bit[i]} has weight {@code 2^i} — matching
 * {@link CircuitAPI#toBinary}/{@link CircuitAPI#fromBinary}. The public API exchanges data in
 * SHA's canonical <b>big-endian bit order</b> (bit 0 = the most-significant bit of byte 0);
 * the endianness conversion between the two lives entirely inside {@link #hashBits}.
 *
 * <h2>Soundness</h2>
 * Every input message bit is asserted boolean, so a malicious prover cannot smuggle a
 * non-{0,1} value through the bitwise operations. Padding bits are compile-time constants.
 *
 * <h2>Cost</h2>
 * Dominated by (a) the 64-bit modular additions — each is one {@code toBinary} range/carry
 * decomposition — and (b) the {@code XOR}/{@code AND} bit gates in Σ/σ/Ch/Maj. Rotations and
 * shifts are free (index re-labelling). Measured cost is reported by the test suite.
 *
 * @see <a href="https://csrc.nist.gov/publications/detail/fips/180/4/final">FIPS 180-4</a>
 */
public final class Sha512 {

    private Sha512() {}

    private static final int WORD_BITS = 64;
    private static final int BLOCK_BITS = 1024;
    private static final int DIGEST_BITS = 512;

    /** SHA-512 initial hash value H(0), FIPS 180-4 §5.3.5. */
    private static final long[] IV = {
            0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
            0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    /** SHA-512 round constants K, FIPS 180-4 §4.2.3. */
    private static final long[] K = {
            0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
            0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
            0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
            0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
            0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
            0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
            0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
            0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
            0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
            0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
            0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
            0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
            0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
            0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
            0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
            0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L
    };

    // ---------------------------------------------------------------------
    // Public API
    // ---------------------------------------------------------------------

    /**
     * SHA-512 of a byte-aligned message supplied as bits in SHA's big-endian bit order
     * (bit 0 = MSB of byte 0). {@code messageBits.length} must be a non-negative multiple of 8.
     * Every input bit is asserted boolean. Returns the 512-bit digest in the same bit order.
     */
    public static Variable[] hashBits(CircuitAPI api, Variable[] messageBits) {
        int msgLen = messageBits.length;
        if (msgLen % 8 != 0)
            throw new IllegalArgumentException("messageBits length must be a multiple of 8 (byte-aligned), got " + msgLen);
        for (Variable b : messageBits) api.assertBoolean(b);

        // --- Padding (FIPS 180-4 §5.1.2): append 1 bit, then zeros, then 128-bit length. ---
        // Total padded length is the least multiple of 1024 that fits msgLen + 1 + 128.
        int totalLen = msgLen + 1 + 128;
        int padded = ((totalLen + BLOCK_BITS - 1) / BLOCK_BITS) * BLOCK_BITS;
        Variable[] bits = new Variable[padded];
        Variable zero = api.constant(0);
        Variable one = api.constant(1);
        System.arraycopy(messageBits, 0, bits, 0, msgLen);
        bits[msgLen] = one;
        for (int i = msgLen + 1; i < padded - 128; i++) bits[i] = zero;
        // 128-bit big-endian message length. msgLen fits in a Java long, so the top 64 bits are 0.
        for (int i = 0; i < 64; i++) bits[padded - 128 + i] = zero;      // high 64 bits of length
        long lenBits = (long) msgLen;
        for (int i = 0; i < 64; i++) {
            // big-endian: bit at offset i is bit (63 - i) of lenBits
            long bit = (lenBits >>> (63 - i)) & 1L;
            bits[padded - 64 + i] = (bit == 1L) ? one : zero;
        }

        // --- Process blocks. ---
        Variable[][] h = new Variable[8][];
        for (int i = 0; i < 8; i++) h[i] = constWord(api, IV[i]);

        int numBlocks = padded / BLOCK_BITS;
        for (int blk = 0; blk < numBlocks; blk++) {
            h = processBlock(api, h, bits, blk * BLOCK_BITS);
        }

        // --- Serialize digest: H0..H7 as big-endian words in SHA bit order. ---
        Variable[] out = new Variable[DIGEST_BITS];
        for (int w = 0; w < 8; w++) shaOrderFromWord(h[w], out, w * WORD_BITS);
        return out;
    }

    /**
     * SHA-512 of a message supplied as bytes (each a field element in [0,255]). Each byte is
     * range-checked to 8 bits. Returns the 64-byte digest as field elements (each in [0,255]).
     */
    public static Variable[] hashBytes(CircuitAPI api, Variable[] messageBytes) {
        Variable[] msgBits = new Variable[messageBytes.length * 8];
        for (int i = 0; i < messageBytes.length; i++) {
            // toBinary gives LSB-first + range-checks the byte to 8 bits; SHA wants MSB-first.
            Variable[] le = api.toBinary(messageBytes[i], 8);
            for (int p = 0; p < 8; p++) msgBits[i * 8 + p] = le[7 - p];
        }
        Variable[] digestBits = hashBits(api, msgBits);
        Variable[] outBytes = new Variable[DIGEST_BITS / 8];
        for (int i = 0; i < outBytes.length; i++) {
            // Reassemble each output byte from its 8 SHA-order (MSB-first) bits.
            Variable[] le = new Variable[8];
            for (int p = 0; p < 8; p++) le[p] = digestBits[i * 8 + (7 - p)];
            outBytes[i] = api.fromBinary(le);
        }
        return outBytes;
    }

    // ---------------------------------------------------------------------
    // Block compression
    // ---------------------------------------------------------------------

    private static Variable[][] processBlock(CircuitAPI api, Variable[][] h, Variable[] bits, int off) {
        // Message schedule W[0..79], each a 64-bit LSB-first word.
        Variable[][] w = new Variable[80][];
        for (int t = 0; t < 16; t++) w[t] = wordFromShaOrder(bits, off + t * WORD_BITS);
        for (int t = 16; t < 80; t++) {
            Variable[] s0 = smallSigma0(api, w[t - 15]);
            Variable[] s1 = smallSigma1(api, w[t - 2]);
            w[t] = addMod64(api, s1, w[t - 7], s0, w[t - 16]);
        }

        Variable[] a = h[0], b = h[1], c = h[2], d = h[3];
        Variable[] e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int t = 0; t < 80; t++) {
            Variable[] t1 = addMod64(api, hh, bigSigma1(api, e), ch(api, e, f, g), constWord(api, K[t]), w[t]);
            Variable[] t2 = addMod64(api, bigSigma0(api, a), maj(api, a, b, c));
            hh = g;
            g = f;
            f = e;
            e = addMod64(api, d, t1);
            d = c;
            c = b;
            b = a;
            a = addMod64(api, t1, t2);
        }

        Variable[][] out = new Variable[8][];
        out[0] = addMod64(api, h[0], a);
        out[1] = addMod64(api, h[1], b);
        out[2] = addMod64(api, h[2], c);
        out[3] = addMod64(api, h[3], d);
        out[4] = addMod64(api, h[4], e);
        out[5] = addMod64(api, h[5], f);
        out[6] = addMod64(api, h[6], g);
        out[7] = addMod64(api, h[7], hh);
        return out;
    }

    // ---------------------------------------------------------------------
    // SHA round functions (operate on LSB-first 64-bit words)
    // ---------------------------------------------------------------------

    private static Variable[] bigSigma0(CircuitAPI api, Variable[] x) {
        return xor(api, xor(api, rotr(x, 28), rotr(x, 34)), rotr(x, 39));
    }

    private static Variable[] bigSigma1(CircuitAPI api, Variable[] x) {
        return xor(api, xor(api, rotr(x, 14), rotr(x, 18)), rotr(x, 41));
    }

    private static Variable[] smallSigma0(CircuitAPI api, Variable[] x) {
        return xor(api, xor(api, rotr(x, 1), rotr(x, 8)), shr(api, x, 7));
    }

    private static Variable[] smallSigma1(CircuitAPI api, Variable[] x) {
        return xor(api, xor(api, rotr(x, 19), rotr(x, 61)), shr(api, x, 6));
    }

    /** Ch(e,f,g) = (e AND f) XOR ((NOT e) AND g). */
    private static Variable[] ch(CircuitAPI api, Variable[] e, Variable[] f, Variable[] g) {
        Variable[] r = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) {
            Variable ef = api.and(e[i], f[i]);
            Variable ng = api.and(api.not(e[i]), g[i]);
            r[i] = api.xor(ef, ng);
        }
        return r;
    }

    /** Maj(a,b,c) = (a AND b) XOR (a AND c) XOR (b AND c). */
    private static Variable[] maj(CircuitAPI api, Variable[] a, Variable[] b, Variable[] c) {
        Variable[] r = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) {
            Variable ab = api.and(a[i], b[i]);
            Variable ac = api.and(a[i], c[i]);
            Variable bc = api.and(b[i], c[i]);
            r[i] = api.xor(api.xor(ab, ac), bc);
        }
        return r;
    }

    // ---------------------------------------------------------------------
    // Bit / word helpers
    // ---------------------------------------------------------------------

    /** Circular right-rotate of a 64-bit value: result bit k = old bit (k+n) mod 64. */
    static Variable[] rotr(Variable[] w, int n) {
        n %= WORD_BITS;
        Variable[] r = new Variable[WORD_BITS];
        for (int k = 0; k < WORD_BITS; k++) r[k] = w[(k + n) % WORD_BITS];
        return r;
    }

    /** Logical right-shift of a 64-bit value: result bit k = old bit (k+n), or 0 if k+n >= 64. */
    static Variable[] shr(CircuitAPI api, Variable[] w, int n) {
        Variable zero = api.constant(0);
        Variable[] r = new Variable[WORD_BITS];
        for (int k = 0; k < WORD_BITS; k++) r[k] = (k + n < WORD_BITS) ? w[k + n] : zero;
        return r;
    }

    private static Variable[] xor(CircuitAPI api, Variable[] a, Variable[] b) {
        Variable[] r = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) r[i] = api.xor(a[i], b[i]);
        return r;
    }

    /**
     * Modular addition of several 64-bit words mod 2^64. Words are summed as field elements
     * (free), then a single decomposition splits value and carry; the low 64 bits are returned.
     */
    private static Variable[] addMod64(CircuitAPI api, Variable[]... words) {
        Variable sum = api.constant(0);
        for (Variable[] w : words) sum = api.add(sum, api.fromBinary(w));
        int extra = 0;
        while ((1 << extra) < words.length) extra++;   // ceil(log2(#addends))
        Variable[] full = api.toBinary(sum, WORD_BITS + extra);
        Variable[] low = new Variable[WORD_BITS];
        System.arraycopy(full, 0, low, 0, WORD_BITS);
        return low;
    }

    /** Build a 64-bit constant word (LSB-first bits). */
    private static Variable[] constWord(CircuitAPI api, long value) {
        Variable[] w = new Variable[WORD_BITS];
        Variable zero = api.constant(0);
        Variable one = api.constant(1);
        for (int i = 0; i < WORD_BITS; i++) w[i] = (((value >>> i) & 1L) == 1L) ? one : zero;
        return w;
    }

    /**
     * Read a 64-bit word from a big-endian SHA bit array into an LSB-first word.
     * SHA bit at offset {@code off+p} (p=0 is the MSB) has value weight 2^(63-p), so
     * LSB-first {@code word[k] = shaBits[off + (63 - k)]}.
     */
    private static Variable[] wordFromShaOrder(Variable[] shaBits, int off) {
        Variable[] w = new Variable[WORD_BITS];
        for (int k = 0; k < WORD_BITS; k++) w[k] = shaBits[off + (WORD_BITS - 1 - k)];
        return w;
    }

    /** Inverse of {@link #wordFromShaOrder}: write an LSB-first word into a SHA-order bit array. */
    private static void shaOrderFromWord(Variable[] word, Variable[] shaBits, int off) {
        for (int p = 0; p < WORD_BITS; p++) shaBits[off + p] = word[WORD_BITS - 1 - p];
    }
}
