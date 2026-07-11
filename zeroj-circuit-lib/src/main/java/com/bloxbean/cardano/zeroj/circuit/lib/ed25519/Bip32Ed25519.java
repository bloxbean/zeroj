package com.bloxbean.cardano.zeroj.circuit.lib.ed25519;

import com.bloxbean.cardano.zeroj.circuit.CircuitAPI;
import com.bloxbean.cardano.zeroj.circuit.Variable;
import com.bloxbean.cardano.zeroj.circuit.lib.hash.HmacSha512;

/**
 * In-circuit BIP32-Ed25519 (Khovratovich–Law / CIP-1852) child key derivation.
 *
 * <p>Given a parent extended key {@code (kL, kR, chainCode)} — all 32-byte little-endian — and a
 * child index, derives the child {@code (kL', kR', chainCode')} exactly as cardano-client-lib's
 * {@code HdKeyGenerator.getChildKeyPair}:</p>
 * <ul>
 *   <li><b>Hardened</b> ({@code i ≥ 2^31}): {@code Z = HMAC-SHA512(cc, 0x00‖kL‖kR‖ser32LE(i))},
 *       {@code c = HMAC-SHA512(cc, 0x01‖kL‖kR‖ser32LE(i))[32:64]} — no EC operation.</li>
 *   <li><b>Soft</b> ({@code i < 2^31}): {@code Z = HMAC-SHA512(cc, 0x02‖A‖ser32LE(i))},
 *       {@code c = …0x03…[32:64]}, where {@code A} is the 32-byte encoded parent public key
 *       {@code encode(kL·B)} — one fixed-base scalar multiplication.</li>
 * </ul>
 * Then {@code kL' = (8·LE(Z[0:28]) + LE(kL)) mod 2^256} and
 * {@code kR' = (LE(Z[32:64]) + LE(kR)) mod 2^256}, and {@code chainCode' = c}.
 *
 * <p>All values are 32 little-endian bytes ({@code byte[0]} = least significant), each a field
 * element in [0,255] (range-checked at entry). The 256-bit additions are byte-wise with carry.</p>
 */
public final class Bip32Ed25519 {

    private Bip32Ed25519() {}

    /** Child extended key: three 32-byte little-endian arrays. */
    public record ChildKey(Variable[] kL, Variable[] kR, Variable[] chainCode) {}

    /** Hardened derivation (no scalar multiplication). */
    public static ChildKey deriveHardened(CircuitAPI api, Variable[] kL, Variable[] kR,
                                          Variable[] chainCode, long childIndex) {
        rangeCheckBytes(api, kL, 32);
        rangeCheckBytes(api, kR, 32);
        rangeCheckBytes(api, chainCode, 32);
        Variable[] idx = ser32LE(api, childIndex);
        // data = tag ‖ kL ‖ kR ‖ idx  (tag 0x00 for Z, 0x01 for c)
        Variable[] dataZ = concat(api.constant(0x00), kL, kR, idx);
        Variable[] dataC = concat(api.constant(0x01), kL, kR, idx);
        return finishDerive(api, chainCode, dataZ, dataC, kL, kR);
    }

    /**
     * {@link #deriveHardened(CircuitAPI, Variable[], Variable[], Variable[], long)} with the
     * child <b>number</b> as an in-circuit witness: four little-endian bytes of the plain
     * (soft-range) value {@code n < 2^31} — the gadget applies the hardening itself
     * ({@code n' = n + 2^31}) by setting the top bit in-circuit, so a prover can neither reach
     * the soft index space here nor pass an already-hardened value.
     */
    public static ChildKey deriveHardened(CircuitAPI api, Variable[] kL, Variable[] kR,
                                          Variable[] chainCode, Variable[] numLE4) {
        rangeCheckBytes(api, kL, 32);
        rangeCheckBytes(api, kR, 32);
        rangeCheckBytes(api, chainCode, 32);
        if (numLE4.length != 4) throw new IllegalArgumentException("child number must be 4 LE bytes");
        for (int i = 0; i < 3; i++) api.assertInRange(numLE4[i], 8);
        api.assertInRange(numLE4[3], 7); // n < 2^31, so the hardened bit below cannot carry
        Variable[] idx = {numLE4[0], numLE4[1], numLE4[2],
                api.add(numLE4[3], api.constant(0x80))}; // set the hardened bit in-circuit
        Variable[] dataZ = concat(api.constant(0x00), kL, kR, idx);
        Variable[] dataC = concat(api.constant(0x01), kL, kR, idx);
        return finishDerive(api, chainCode, dataZ, dataC, kL, kR);
    }

    /**
     * Soft derivation with the parent public key {@code apEncoded} (32-byte encoded {@code kL·B})
     * supplied directly. Compose with {@link Ed25519Point#scalarMulFixedBaseB}+{@code encode} to
     * obtain {@code apEncoded}; kept separate so the (cheap) HMAC+bignum logic can be validated
     * without the (heavy) in-circuit scalar multiplication.
     */
    public static ChildKey deriveSoft(CircuitAPI api, Variable[] kL, Variable[] kR,
                                      Variable[] chainCode, Variable[] apEncoded, long childIndex) {
        rangeCheckBytes(api, kL, 32);
        rangeCheckBytes(api, kR, 32);
        rangeCheckBytes(api, chainCode, 32);
        rangeCheckBytes(api, apEncoded, 32);
        Variable[] idx = ser32LE(api, childIndex);
        Variable[] dataZ = concat(api.constant(0x02), apEncoded, idx);
        Variable[] dataC = concat(api.constant(0x03), apEncoded, idx);
        return finishDerive(api, chainCode, dataZ, dataC, kL, kR);
    }

    /**
     * {@link #deriveSoft(CircuitAPI, Variable[], Variable[], Variable[], Variable[], long)} with
     * the child index as an <b>in-circuit witness</b>: four little-endian bytes. The gadget
     * constrains it to a valid soft index (bytes in range, top bit of the most significant byte
     * zero, i.e. {@code index < 2^31}) — a hardened index cannot be smuggled through the soft
     * path.
     */
    public static ChildKey deriveSoft(CircuitAPI api, Variable[] kL, Variable[] kR,
                                      Variable[] chainCode, Variable[] apEncoded, Variable[] idxLE4) {
        rangeCheckBytes(api, kL, 32);
        rangeCheckBytes(api, kR, 32);
        rangeCheckBytes(api, chainCode, 32);
        rangeCheckBytes(api, apEncoded, 32);
        if (idxLE4.length != 4) throw new IllegalArgumentException("index must be 4 LE bytes");
        for (int i = 0; i < 3; i++) api.assertInRange(idxLE4[i], 8);
        api.assertInRange(idxLE4[3], 7); // MSB < 0x80 => soft index (< 2^31)
        Variable[] dataZ = concat(api.constant(0x02), apEncoded, idxLE4);
        Variable[] dataC = concat(api.constant(0x03), apEncoded, idxLE4);
        return finishDerive(api, chainCode, dataZ, dataC, kL, kR);
    }

    /**
     * Full soft derivation computing {@code A = encode(kL·B)} in-circuit (adds ~29M constraints).
     * The scalar is {@code kL} interpreted as a 256-bit little-endian integer.
     */
    public static ChildKey deriveSoftComputingAp(CircuitAPI api, Variable[] kL, Variable[] kR,
                                                 Variable[] chainCode, long childIndex) {
        Variable[] scalarBits = bytesToBitsLE(api, kL); // 256 bits, LSB-first
        Variable[] ap = Ed25519Point.scalarMulFixedBaseBWindowed(api, scalarBits, 4).encode();
        return deriveSoft(api, kL, kR, chainCode, ap, childIndex);
    }

    /** {@link #deriveSoftComputingAp(CircuitAPI, Variable[], Variable[], Variable[], long)} with
     *  the child index as an in-circuit witness (four LE bytes, soft-constrained). */
    public static ChildKey deriveSoftComputingAp(CircuitAPI api, Variable[] kL, Variable[] kR,
                                                 Variable[] chainCode, Variable[] idxLE4) {
        Variable[] scalarBits = bytesToBitsLE(api, kL); // 256 bits, LSB-first
        Variable[] ap = Ed25519Point.scalarMulFixedBaseBWindowed(api, scalarBits, 4).encode();
        return deriveSoft(api, kL, kR, chainCode, ap, idxLE4);
    }

    // ------------------------------------------------------------------

    private static ChildKey finishDerive(CircuitAPI api, Variable[] chainCode,
                                         Variable[] dataZ, Variable[] dataC,
                                         Variable[] kL, Variable[] kR) {
        Variable[] z = HmacSha512.hmacBytes(api, chainCode, dataZ);       // 64 bytes
        Variable[] cFull = HmacSha512.hmacBytes(api, chainCode, dataC);   // 64 bytes

        Variable[] zl = new Variable[28];
        System.arraycopy(z, 0, zl, 0, 28);
        Variable[] zr = new Variable[32];
        System.arraycopy(z, 32, zr, 0, 32);
        Variable[] cc = new Variable[32];
        System.arraycopy(cFull, 32, cc, 0, 32);

        Variable[] eightZl = mulBy8(api, zl);                 // 32 bytes
        Variable[] kLchild = add256(api, eightZl, kL);        // (8·ZL + kL) mod 2^256
        Variable[] kRchild = add256(api, zr, kR);             // (ZR + kR) mod 2^256
        return new ChildKey(kLchild, kRchild, cc);
    }

    /** Multiply a little-endian byte number by 8, result truncated to 32 bytes (mod 2^256). */
    private static Variable[] mulBy8(CircuitAPI api, Variable[] in) {
        Variable carry = api.constant(0);
        Variable[] out = new Variable[32];
        for (int i = 0; i < 32; i++) {
            Variable src = (i < in.length) ? in[i] : api.constant(0);
            Variable v = api.add(api.mul(src, api.constant(8)), carry); // < 8·256 + carry < 2^12
            Variable[] bits = api.toBinary(v, 12);
            out[i] = api.fromBinary(slice(bits, 0, 8));
            carry = api.fromBinary(slice(bits, 8, 12));
        }
        return out; // final carry dropped => mod 2^256
    }

    /** Add two 32-byte little-endian numbers, truncated to 32 bytes (mod 2^256). */
    private static Variable[] add256(CircuitAPI api, Variable[] a, Variable[] b) {
        Variable carry = api.constant(0);
        Variable[] out = new Variable[32];
        for (int i = 0; i < 32; i++) {
            Variable s = api.add(api.add(a[i], b[i]), carry); // < 256 + 256 + 1
            Variable[] bits = api.toBinary(s, 9);
            out[i] = api.fromBinary(slice(bits, 0, 8));
            carry = bits[8];
        }
        return out; // final carry dropped => mod 2^256
    }

    private static Variable[] ser32LE(CircuitAPI api, long index) {
        Variable[] out = new Variable[4];
        for (int i = 0; i < 4; i++) out[i] = api.constant((index >>> (8 * i)) & 0xff);
        return out;
    }

    private static Variable[] bytesToBitsLE(CircuitAPI api, Variable[] bytes) {
        Variable[] bits = new Variable[bytes.length * 8];
        for (int i = 0; i < bytes.length; i++) {
            Variable[] lb = api.toBinary(bytes[i], 8);
            System.arraycopy(lb, 0, bits, i * 8, 8);
        }
        return bits;
    }

    private static void rangeCheckBytes(CircuitAPI api, Variable[] bytes, int n) {
        if (bytes.length != n) throw new IllegalArgumentException("expected " + n + " bytes, got " + bytes.length);
        for (Variable b : bytes) api.assertInRange(b, 8);
    }

    private static Variable[] concat(Variable head, Variable[]... rest) {
        int len = 1;
        for (Variable[] r : rest) len += r.length;
        Variable[] out = new Variable[len];
        out[0] = head;
        int p = 1;
        for (Variable[] r : rest) { System.arraycopy(r, 0, out, p, r.length); p += r.length; }
        return out;
    }

    private static Variable[] slice(Variable[] a, int from, int toExclusive) {
        Variable[] out = new Variable[toExclusive - from];
        System.arraycopy(a, from, out, 0, out.length);
        return out;
    }
}
