package org.zeroj.circuit.lib.hash;

import org.zeroj.circuit.CircuitAPI;
import org.zeroj.circuit.Variable;

/**
 * In-circuit SHA-256 (FIPS 180-4), returning the complete standard digest.
 *
 * <p>The public interfaces use SHA's big-endian byte/bit order. Internally a 32-bit
 * word is an LSB-first {@code Variable[32]}, matching {@link CircuitAPI#toBinary}
 * and {@link CircuitAPI#fromBinary}. Message length is fixed at circuit definition.
 *
 * <h2>Soundness</h2>
 * Input bits are constrained boolean and input bytes are range-checked. Padding,
 * the 64-bit length suffix and round constants are circuit constants. Every modular
 * addition decomposes the whole sum including its carry before retaining its low
 * 32 bits. At most seven words are summed, so values stay below 2^35, well below
 * ZeroJ's supported scalar fields. No host hash or unconstrained witness hint is used.
 * Callers must bind the returned digest to their intended public statement.
 *
 * <h2>Cost and scope</h2>
 * Rotations and shifts only reindex bits; Boolean operations and carry decompositions
 * dominate the constraint cost. This follows {@link Sha512}'s construction and API
 * conventions. It adds no constant-time or production-security guarantee to the DSL.
 *
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">FIPS 180-4 (August 2015)</a>
 */
public final class Sha256 {

    private Sha256() {}

    private static final int WORD_BITS = 32;
    private static final int BLOCK_BITS = 512;
    private static final int DIGEST_BITS = 256;

    /** Initial hash value, FIPS 180-4 section 5.3.3. */
    private static final int[] IV = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    /** Round constants, FIPS 180-4 section 4.2.2. */
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    /**
     * Hash a byte-aligned message supplied MSB-first (bit 0 is the MSB of byte 0).
     * Every input bit is asserted boolean. Returns all 256 digest bits in that order.
     *
     * @throws IllegalArgumentException if the input length is not a multiple of eight
     * @throws ArithmeticException if the padded bit array cannot be indexed by an int
     */
    public static Variable[] hashBits(CircuitAPI api, Variable[] messageBits) {
        int msgLen = messageBits.length;
        int padded = paddedBitLength(msgLen);
        for (Variable bit : messageBits) api.assertBoolean(bit);

        // FIPS 180-4 section 5.1.1: message || 1 || zero padding || BE64(bit length).
        Variable zero = api.constant(0);
        Variable one = api.constant(1);
        Variable[] bits = new Variable[padded];
        System.arraycopy(messageBits, 0, bits, 0, msgLen);
        bits[msgLen] = one;
        for (int i = msgLen + 1; i < padded - 64; i++) bits[i] = zero;
        long lenBits = msgLen;
        for (int i = 0; i < 64; i++)
            bits[padded - 64 + i] = ((lenBits >>> (63 - i)) & 1L) == 0 ? zero : one;

        Variable[][] h = new Variable[8][];
        for (int i = 0; i < h.length; i++) h[i] = constWord(api, IV[i]);
        for (int offset = 0; offset < padded; offset += BLOCK_BITS)
            h = processBlock(api, h, bits, offset);

        Variable[] digest = new Variable[DIGEST_BITS];
        for (int word = 0; word < h.length; word++)
            for (int bit = 0; bit < WORD_BITS; bit++)
                digest[word * WORD_BITS + bit] = h[word][WORD_BITS - 1 - bit];
        return digest;
    }

    /**
     * Hash field-valued bytes, constraining each to [0,255]. Returns all 32 digest
     * bytes, each in [0,255], in standard SHA order. Empty messages are supported.
     *
     * @throws ArithmeticException if the message or padded bit array cannot be indexed by an int
     */
    public static Variable[] hashBytes(CircuitAPI api, Variable[] messageBytes) {
        int bitLength = messageBitLength(messageBytes.length);
        paddedBitLength(bitLength); // Check before allocating or emitting constraints.
        Variable[] bits = new Variable[bitLength];
        for (int i = 0; i < messageBytes.length; i++) {
            Variable[] le = api.toBinary(messageBytes[i], 8);
            for (int bit = 0; bit < 8; bit++) bits[i * 8 + bit] = le[7 - bit];
        }
        // assertBoolean is idempotent in CircuitAPI, including decomposed byte bits.
        Variable[] digestBits = hashBits(api, bits);
        Variable[] digest = new Variable[DIGEST_BITS / 8];
        for (int i = 0; i < digest.length; i++) {
            Variable[] le = new Variable[8];
            for (int bit = 0; bit < 8; bit++) le[bit] = digestBits[i * 8 + 7 - bit];
            digest[i] = api.fromBinary(le);
        }
        return digest;
    }

    // Package-private arithmetic helpers permit boundary tests without huge allocations.
    static int messageBitLength(int byteLength) {
        if (byteLength < 0) throw new IllegalArgumentException("negative message length");
        return Math.multiplyExact(byteLength, 8);
    }

    static int paddedBitLength(int bitLength) {
        if (bitLength < 0 || bitLength % 8 != 0)
            throw new IllegalArgumentException("messageBits length must be non-negative and byte-aligned");
        long blocks = ((long) bitLength + 1 + 64 + BLOCK_BITS - 1) / BLOCK_BITS;
        return Math.toIntExact(blocks * BLOCK_BITS);
    }

    private static Variable[][] processBlock(CircuitAPI api, Variable[][] h, Variable[] bits, int offset) {
        Variable[][] w = new Variable[64][];
        for (int t = 0; t < 16; t++) {
            w[t] = new Variable[WORD_BITS];
            for (int bit = 0; bit < WORD_BITS; bit++)
                w[t][bit] = bits[offset + t * WORD_BITS + WORD_BITS - 1 - bit];
        }
        for (int t = 16; t < w.length; t++) {
            Variable[] s0 = xor3(api, rotr(w[t - 15], 7), rotr(w[t - 15], 18), shr(api, w[t - 15], 3));
            Variable[] s1 = xor3(api, rotr(w[t - 2], 17), rotr(w[t - 2], 19), shr(api, w[t - 2], 10));
            w[t] = addMod32(api, s1, w[t - 7], s0, w[t - 16]);
        }

        Variable[] a = h[0], b = h[1], c = h[2], d = h[3];
        Variable[] e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int t = 0; t < w.length; t++) {
            Variable[] s1 = xor3(api, rotr(e, 6), rotr(e, 11), rotr(e, 25));
            Variable t1 = sumWords(api, hh, s1, ch(api, e, f, g), constWord(api, K[t]), w[t]);
            Variable[] s0 = xor3(api, rotr(a, 2), rotr(a, 13), rotr(a, 22));
            Variable t2 = sumWords(api, s0, maj(api, a, b, c));
            hh = g;
            g = f;
            f = e;
            // T1 has five w-bit addends; T1+d has six. Decompose the exact sum,
            // including three carry bits, only where the next state needs bits.
            e = lowWord(api, api.add(api.fromBinary(d), t1), 3);
            d = c;
            c = b;
            b = a;
            // T1+T2 has seven w-bit addends, below 2^(w+3) and the field modulus.
            a = lowWord(api, api.add(t1, t2), 3);
        }
        return new Variable[][]{
                addMod32(api, h[0], a), addMod32(api, h[1], b),
                addMod32(api, h[2], c), addMod32(api, h[3], d),
                addMod32(api, h[4], e), addMod32(api, h[5], f),
                addMod32(api, h[6], g), addMod32(api, h[7], hh)
        };
    }

    /** Ch(e,f,g) = g + e(f-g), a Boolean selection for Boolean inputs. */
    private static Variable[] ch(CircuitAPI api, Variable[] e, Variable[] f, Variable[] g) {
        Variable[] result = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++)
            result[i] = api.add(g[i], api.mul(e[i], api.sub(f[i], g[i])));
        return result;
    }

    /** Maj(a,b,c) = ab + c(a+b-2ab): two products, Boolean for Boolean inputs. */
    static Variable[] maj(CircuitAPI api, Variable[] a, Variable[] b, Variable[] c) {
        Variable[] result = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) {
            Variable ab = api.mul(a[i], b[i]);
            Variable xor = api.sub(api.add(a[i], b[i]), api.add(ab, ab));
            result[i] = api.add(ab, api.mul(c[i], xor));
        }
        return result;
    }

    private static Variable[] xor3(CircuitAPI api, Variable[] a, Variable[] b, Variable[] c) {
        Variable[] result = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) result[i] = api.xor(api.xor(a[i], b[i]), c[i]);
        return result;
    }

    /** Circular right rotation of an LSB-first 32-bit word. Internal shifts are nonnegative. */
    static Variable[] rotr(Variable[] word, int distance) {
        Variable[] result = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) result[i] = word[(i + distance) % WORD_BITS];
        return result;
    }

    /** Logical right shift of an LSB-first 32-bit word. */
    static Variable[] shr(CircuitAPI api, Variable[] word, int distance) {
        Variable zero = api.constant(0);
        Variable[] result = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) result[i] = i + distance < WORD_BITS ? word[i + distance] : zero;
        return result;
    }

    private static Variable[] constWord(CircuitAPI api, int value) {
        Variable zero = api.constant(0);
        Variable one = api.constant(1);
        Variable[] word = new Variable[WORD_BITS];
        for (int i = 0; i < WORD_BITS; i++) word[i] = ((value >>> i) & 1) == 0 ? zero : one;
        return word;
    }

    /** The complete sum is range-constrained before discarding the carry. */
    private static Variable[] addMod32(CircuitAPI api, Variable[]... words) {
        int carryBits = 32 - Integer.numberOfLeadingZeros(words.length - 1);
        return lowWord(api, sumWords(api, words), carryBits);
    }

    /** Exact integer sum of already-Boolean words; callers bound the number of addends. */
    private static Variable sumWords(CircuitAPI api, Variable[]... words) {
        Variable sum = api.constant(0);
        for (Variable[] word : words) sum = api.add(sum, api.fromBinary(word));
        return sum;
    }

    /** Fully constrain the bounded sum, including carries, before retaining its low word. */
    private static Variable[] lowWord(CircuitAPI api, Variable sum, int carryBits) {
        Variable[] full = api.toBinary(sum, WORD_BITS + carryBits);
        Variable[] low = new Variable[WORD_BITS];
        System.arraycopy(full, 0, low, 0, WORD_BITS);
        return low;
    }
}
