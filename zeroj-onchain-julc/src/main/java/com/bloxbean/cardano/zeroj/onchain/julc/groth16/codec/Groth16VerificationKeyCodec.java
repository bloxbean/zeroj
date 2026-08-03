package com.bloxbean.cardano.zeroj.onchain.julc.groth16.codec;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Canonical byte encoding for a Cardano BLS12-381 Groth16 verification key.
 *
 * <p>{@code zeroj-groth16-vk-bls12-381-v1} is, in order: the eight ASCII bytes
 * {@code ZJG16VK1}, a four-byte unsigned big-endian IC count, compressed alpha
 * G1 (48 bytes), beta/gamma/delta G2 (96 bytes each), then that many compressed
 * IC G1 points (48 bytes each). No trailing bytes are permitted.</p>
 */
public final class Groth16VerificationKeyCodec {
    public static final String FORMAT = "zeroj-groth16-vk-bls12-381-v1";
    private static final byte[] MAGIC = "ZJG16VK1".getBytes(StandardCharsets.US_ASCII);
    private static final int G1_BYTES = 48;
    private static final int G2_BYTES = 96;
    private static final int FIXED_BYTES = MAGIC.length + Integer.BYTES + G1_BYTES + 3 * G2_BYTES;
    private static final int MAX_IC_POINTS = 1 << 20;

    private Groth16VerificationKeyCodec() {}

    public static byte[] encode(SnarkjsToCardano.VkCompressed key) {
        Objects.requireNonNull(key, "key");
        requireLength("alpha", key.alpha(), G1_BYTES);
        requireLength("beta", key.beta(), G2_BYTES);
        requireLength("gamma", key.gamma(), G2_BYTES);
        requireLength("delta", key.delta(), G2_BYTES);
        List<byte[]> ic = List.copyOf(Objects.requireNonNull(key.ic(), "ic"));
        if (ic.isEmpty() || ic.size() > MAX_IC_POINTS) {
            throw new IllegalArgumentException("IC count must be in [1, " + MAX_IC_POINTS + "]");
        }
        for (int index = 0; index < ic.size(); index++) {
            requireLength("ic[" + index + "]", ic.get(index), G1_BYTES);
        }
        int size = Math.toIntExact(Math.addExact(
                FIXED_BYTES, Math.multiplyExact((long) ic.size(), G1_BYTES)));
        ByteBuffer output = ByteBuffer.allocate(size).order(ByteOrder.BIG_ENDIAN);
        output.put(MAGIC).putInt(ic.size());
        output.put(key.alpha()).put(key.beta()).put(key.gamma()).put(key.delta());
        for (byte[] point : ic) output.put(point);
        return output.array();
    }

    public static SnarkjsToCardano.VkCompressed decode(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length < FIXED_BYTES + G1_BYTES) {
            throw new IllegalArgumentException("truncated Groth16 verification key");
        }
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = take(input, MAGIC.length);
        if (!Arrays.equals(MAGIC, magic)) {
            throw new IllegalArgumentException("invalid Groth16 verification-key magic");
        }
        int icCount = input.getInt();
        if (icCount < 1 || icCount > MAX_IC_POINTS) {
            throw new IllegalArgumentException("invalid Groth16 verification-key IC count");
        }
        long expected = Math.addExact(FIXED_BYTES, Math.multiplyExact((long) icCount, G1_BYTES));
        if (expected != encoded.length) {
            throw new IllegalArgumentException("Groth16 verification-key length does not match IC count");
        }
        byte[] alpha = take(input, G1_BYTES);
        byte[] beta = take(input, G2_BYTES);
        byte[] gamma = take(input, G2_BYTES);
        byte[] delta = take(input, G2_BYTES);
        List<byte[]> ic = new ArrayList<>(icCount);
        for (int index = 0; index < icCount; index++) ic.add(take(input, G1_BYTES));
        if (input.hasRemaining()) throw new IllegalArgumentException("trailing verification-key bytes");
        return new SnarkjsToCardano.VkCompressed(alpha, beta, gamma, delta, List.copyOf(ic));
    }

    private static void requireLength(String name, byte[] value, int expected) {
        if (value == null || value.length != expected) {
            throw new IllegalArgumentException(name + " must be " + expected + " bytes");
        }
    }

    private static byte[] take(ByteBuffer input, int count) {
        byte[] value = new byte[count];
        input.get(value);
        return value;
    }
}
