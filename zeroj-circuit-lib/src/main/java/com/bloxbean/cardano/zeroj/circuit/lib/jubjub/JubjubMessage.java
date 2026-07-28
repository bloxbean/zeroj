package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Canonical public message field element for the ZeroJ Jubjub EdDSA suite.
 *
 * <p>The signature scheme signs a field element, not an untyped byte string. The two
 * factories therefore force callers to choose between an already-canonical field element and
 * the suite's versioned prehash-to-field operation. The selected factory is not encoded in a
 * signature; verifiers starting from an application payload must repeat the same preprocessing.
 *
 * <p>Instances contain only public data and are immutable. Mutable inputs and returned
 * encodings are defensively copied.
 */
public final class JubjubMessage {

    /** Canonical field encoding length, unsigned big-endian. */
    public static final int CANONICAL_BYTES = 32;

    private static final byte[] HASH_TO_FIELD_DST =
            EdDSAJubjub.HASH_TO_FIELD_DST.getBytes(StandardCharsets.US_ASCII);

    private final byte[] canonical;

    private JubjubMessage(byte[] canonical, boolean owned) {
        this.canonical = owned ? canonical : canonical.clone();
    }

    /**
     * Constructs a message from exactly 32 unsigned big-endian bytes.
     *
     * @throws IllegalArgumentException if the length is not 32 or the encoded value is at
     *                                  least the Jubjub base-field modulus
     */
    public static JubjubMessage fromCanonicalFieldBytes(byte[] encodedFieldElement) {
        Objects.requireNonNull(encodedFieldElement, "encodedFieldElement");
        if (encodedFieldElement.length != CANONICAL_BYTES) {
            throw new IllegalArgumentException(
                    "canonical Jubjub message must be exactly 32 bytes");
        }
        byte[] owned = encodedFieldElement.clone();
        long[] field = new long[CtJubjubFqOps.LIMBS];
        long[] work = new long[5];
        long canonicalMask = CtJubjubFqOps.fromCanonicalBytes(
                field, 0, owned, 0, work, 0);
        CtMontgomery256Ops.wipe(field);
        CtMontgomery256Ops.wipe(work);
        if (canonicalMask != -1L) {
            Arrays.fill(owned, (byte) 0);
            throw new IllegalArgumentException(
                    "canonical Jubjub message must encode a value in [0,p)");
        }
        return new JubjubMessage(owned, true);
    }

    /**
     * Maps an arbitrary payload to the suite message field using the versioned v1 mapping:
     *
     * <pre>
     * wide = SHA-512(I2OSP(len(DST),1) || DST || I2OSP(len(message),8) || message)
     * out  = OS2IP_BE(wide) mod p
     * </pre>
     *
     * <p>The signature binds {@code out}, not the original bytes or factory choice.
     */
    public static JubjubMessage hashToField(byte[] message) {
        Objects.requireNonNull(message, "message");
        if (HASH_TO_FIELD_DST.length > 255) {
            throw new IllegalStateException("hash-to-field DST must fit one byte");
        }
        MessageDigest sha512;
        try {
            sha512 = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 is required but unavailable", e);
        }
        sha512.update((byte) HASH_TO_FIELD_DST.length);
        sha512.update(HASH_TO_FIELD_DST);
        sha512.update(ByteBuffer.allocate(Long.BYTES).putLong(message.length).array());
        byte[] wide = sha512.digest(message);
        BigInteger mapped = new BigInteger(1, wide).mod(JubjubCurve.BASE_FIELD_PRIME);
        Arrays.fill(wide, (byte) 0);
        return new JubjubMessage(fixed32(mapped), true);
    }

    /** Returns a defensive copy of the canonical unsigned big-endian field encoding. */
    public byte[] toCanonicalFieldBytes() {
        return canonical.clone();
    }

    /**
     * Returns the canonical public field element represented by this message.
     *
     * <p>This is the explicit bridge for circuit public/witness inputs and compatibility APIs
     * that still accept {@link BigInteger}. It never hashes or reduces. Hardened secret code
     * imports {@link #canonical} through {@link #copyCanonicalTo(byte[], int)} instead.
     */
    public BigInteger toPublicFieldElement() {
        return new BigInteger(1, canonical);
    }

    void copyCanonicalTo(byte[] output, int offset) {
        System.arraycopy(canonical, 0, output, offset, CANONICAL_BYTES);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof JubjubMessage message
                && Arrays.equals(canonical, message.canonical);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(canonical);
    }

    @Override
    public String toString() {
        return "JubjubMessage[fieldElement=<public>]";
    }

    private static byte[] fixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[CANONICAL_BYTES];
        int source = raw.length == CANONICAL_BYTES + 1 ? 1 : 0;
        System.arraycopy(raw, source, out, out.length - (raw.length - source),
                raw.length - source);
        return out;
    }
}
