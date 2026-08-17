package com.bloxbean.cardano.zeroj.circuit.lib.poseidon;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Stable fingerprint for a complete Poseidon parameter bundle.
 *
 * <p>The encoding is deliberately independent of Java serialization:
 * The exact preimage is {@code len(tag) || tag || len(curve) || curve || t ||
 * alpha || rf || rp || len(modulus) || modulus || C || M}. Lengths and the
 * four parameter integers are unsigned 32-bit big-endian values. The C/M
 * element counts are derived from {@code t/rf/rp}, so those fixed-width arrays
 * are not separately length-prefixed. Field elements are canonical unsigned
 * big-endian values whose width is the field modulus width. The fingerprint
 * is compatibility metadata and is not used as a circuit commitment.
 */
public final class PoseidonParameterFingerprint {
    private PoseidonParameterFingerprint() {}

    public static String sha256(PoseidonParams params) {
        Objects.requireNonNull(params, "params");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            putBytes(digest, "zeroj-poseidon-parameter-fingerprint-v1".getBytes(StandardCharsets.US_ASCII));
            putBytes(digest, params.field().curve().name().getBytes(StandardCharsets.US_ASCII));
            digest.update(ByteBuffer.allocate(16)
                    .putInt(params.t())
                    .putInt(params.alpha())
                    .putInt(params.rf())
                    .putInt(params.rp())
                    .array());
            int width = (params.field().prime().bitLength() + 7) / 8;
            putBytes(digest, unsignedFixed(params.field().prime(), width));
            for (BigInteger value : params.c()) digest.update(unsignedFixed(value, width));
            for (BigInteger value : params.m()) digest.update(unsignedFixed(value, width));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** Pre-ADR-0042 metadata fingerprint, accepted only by the explicit benchmark migration. */
    public static String legacySha256(PoseidonParams params) {
        Objects.requireNonNull(params, "params");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(16)
                    .putInt(params.t())
                    .putInt(params.alpha())
                    .putInt(params.rf())
                    .putInt(params.rp())
                    .array());
            int width = (params.field().prime().bitLength() + 7) / 8;
            for (BigInteger value : params.c()) digest.update(unsignedFixed(value, width));
            for (BigInteger value : params.m()) digest.update(unsignedFixed(value, width));
            return HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static void putBytes(MessageDigest digest, byte[] value) {
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(value.length).array());
        digest.update(value);
    }

    static byte[] unsignedFixed(BigInteger value, int width) {
        Objects.requireNonNull(value, "value");
        if (value.signum() < 0 || value.bitLength() > width * 8) {
            throw new IllegalArgumentException("value does not fit the requested unsigned width");
        }
        byte[] encoded = value.toByteArray();
        byte[] output = new byte[width];
        int sourceOffset = encoded.length > width ? encoded.length - width : 0;
        int count = Math.min(encoded.length, width);
        System.arraycopy(encoded, sourceOffset, output, width - count, count);
        return output;
    }
}
