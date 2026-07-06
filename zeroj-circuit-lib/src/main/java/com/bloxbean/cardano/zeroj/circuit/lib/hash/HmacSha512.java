package com.bloxbean.cardano.zeroj.circuit.lib.hash;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;

/**
 * In-circuit HMAC-SHA512 (RFC 2104) gadget, layered on {@link Sha512}.
 *
 * <p>{@code HMAC(K, m) = H((K' ^ opad) ‖ H((K' ^ ipad) ‖ m))} where the SHA-512 block size is
 * 128 bytes, {@code ipad = 0x36} repeated, {@code opad = 0x5c} repeated, and {@code K'} is the
 * key normalized to one block: keys of {@code > 128} bytes are first hashed with SHA-512 to
 * 64 bytes, then (like all keys) zero-padded on the right to 128 bytes.</p>
 *
 * <p>This is the primitive BIP32-Ed25519 child derivation is built from
 * ({@code Z = HMAC-SHA512(chainCode, …)}), where the key (a 32-byte chain code) always takes
 * the short-key path.</p>
 *
 * <p>Field-agnostic, like {@link Sha512}. Every key byte is range-checked to 8 bits as a side
 * effect of the constant-XOR decomposition, so a malicious prover cannot supply an
 * out-of-range key byte.</p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc2104">RFC 2104</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4231">RFC 4231 (HMAC-SHA-2 test vectors)</a>
 */
public final class HmacSha512 {

    private HmacSha512() {}

    private static final int BLOCK_BYTES = 128;
    private static final int DIGEST_BYTES = 64;
    private static final int IPAD = 0x36;
    private static final int OPAD = 0x5c;

    /**
     * HMAC-SHA512 over byte inputs. Each key/message byte is a field element in [0,255];
     * the 64-byte MAC is returned as field elements in [0,255].
     */
    public static Variable[] hmacBytes(CircuitAPI api, Variable[] keyBytes, Variable[] messageBytes) {
        // Step 1: normalize the key to a single 128-byte block K'.
        Variable[] kNorm = (keyBytes.length > BLOCK_BYTES)
                ? Sha512.hashBytes(api, keyBytes)   // 64 bytes, all in-range
                : keyBytes;

        Variable zero = api.constant(0);
        Variable[] kPad = new Variable[BLOCK_BYTES];
        for (int i = 0; i < BLOCK_BYTES; i++) kPad[i] = (i < kNorm.length) ? kNorm[i] : zero;

        // Step 2: inner = H( (K' ^ ipad) ‖ message )
        Variable[] inner = new Variable[BLOCK_BYTES + messageBytes.length];
        for (int i = 0; i < BLOCK_BYTES; i++) inner[i] = xorByteConst(api, kPad[i], IPAD);
        System.arraycopy(messageBytes, 0, inner, BLOCK_BYTES, messageBytes.length);
        Variable[] innerDigest = Sha512.hashBytes(api, inner);

        // Step 3: outer = H( (K' ^ opad) ‖ innerDigest )
        Variable[] outer = new Variable[BLOCK_BYTES + DIGEST_BYTES];
        for (int i = 0; i < BLOCK_BYTES; i++) outer[i] = xorByteConst(api, kPad[i], OPAD);
        System.arraycopy(innerDigest, 0, outer, BLOCK_BYTES, DIGEST_BYTES);
        return Sha512.hashBytes(api, outer);
    }

    /**
     * XOR a byte-valued variable with a constant byte. Decomposes {@code x} to 8 bits
     * (LSB-first, which range-checks {@code x} to [0,255]); for each bit position where the
     * constant is 1, the bit is inverted; then recomposes. When {@code x} is a compile-time
     * zero constant this still produces the correct constant {@code c} cheaply.
     */
    private static Variable xorByteConst(CircuitAPI api, Variable x, int c) {
        Variable[] bits = api.toBinary(x, 8);
        Variable[] out = new Variable[8];
        for (int i = 0; i < 8; i++) {
            boolean cBit = ((c >>> i) & 1) == 1;
            out[i] = cBit ? api.not(bits[i]) : bits[i];
        }
        return api.fromBinary(out);
    }
}
