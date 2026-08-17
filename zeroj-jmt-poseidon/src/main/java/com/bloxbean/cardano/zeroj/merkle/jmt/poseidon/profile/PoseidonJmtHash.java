package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.FastPoseidonBls12381T3;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Canonical total byte hashing and scalar encoding for Poseidon JMT v1. */
public final class PoseidonJmtHash {
    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();

    private PoseidonJmtHash() {}

    public static byte[] digest(byte[] input) {
        return encode(digestField(PoseidonJmtProfile.PARAMS, input));
    }

    public static BigInteger digestField(PoseidonParams params, byte[] input) {
        PoseidonJmtProfile.requireSupported(params);
        Objects.requireNonNull(input, "input");

        List<BigInteger> fixed = fixedChunks(input);
        if (fixed != null) {
            List<BigInteger> fields = new ArrayList<>(2 + PoseidonJmtProfile.FIXED_DIGEST_CHUNKS);
            fields.add(PoseidonJmtProfile.DOMAIN_BYTES);
            fields.add(BigInteger.valueOf(input.length));
            fields.addAll(fixed);
            while (fields.size() < 2 + PoseidonJmtProfile.FIXED_DIGEST_CHUNKS) {
                fields.add(BigInteger.ZERO);
            }
            return foldHash(params, fields.toArray(BigInteger[]::new));
        }

        List<BigInteger> fields = new ArrayList<>(2 +
                (input.length + PoseidonJmtProfile.RAW_BYTES_PER_CHUNK - 1)
                        / PoseidonJmtProfile.RAW_BYTES_PER_CHUNK);
        fields.add(PoseidonJmtProfile.DOMAIN_RAW_BYTES);
        fields.add(BigInteger.valueOf(input.length));
        for (int offset = 0; offset < input.length; offset += PoseidonJmtProfile.RAW_BYTES_PER_CHUNK) {
            int end = Math.min(input.length, offset + PoseidonJmtProfile.RAW_BYTES_PER_CHUNK);
            fields.add(unsigned(Arrays.copyOfRange(input, offset, end)));
        }
        return foldHash(params, fields.toArray(BigInteger[]::new));
    }

    public static BigInteger decode(byte[] digest) {
        Objects.requireNonNull(digest, "digest");
        if (digest.length != PoseidonJmtProfile.DIGEST_BYTES) {
            throw new IllegalArgumentException("JMT digest must be exactly 32 bytes");
        }
        BigInteger value = unsigned(digest);
        if (value.compareTo(PRIME) >= 0) {
            throw new IllegalArgumentException("JMT digest is not a canonical BLS12-381 scalar");
        }
        return value;
    }

    public static byte[] encode(BigInteger field) {
        Objects.requireNonNull(field, "field");
        if (field.signum() < 0 || field.compareTo(PRIME) >= 0) {
            throw new IllegalArgumentException("field must be canonical");
        }
        byte[] raw = field.toByteArray();
        byte[] output = new byte[PoseidonJmtProfile.DIGEST_BYTES];
        int sourceOffset = Math.max(0, raw.length - output.length);
        int count = Math.min(raw.length, output.length);
        System.arraycopy(raw, sourceOffset, output, output.length - count, count);
        return output;
    }

    public static int[] nibbles(byte[] canonicalKeyHash) {
        decode(canonicalKeyHash);
        int[] output = new int[PoseidonJmtProfile.KEY_NIBBLES];
        for (int index = 0; index < canonicalKeyHash.length; index++) {
            int value = canonicalKeyHash[index] & 0xff;
            output[index * 2] = value >>> 4;
            output[index * 2 + 1] = value & 0x0f;
        }
        return output;
    }

    static BigInteger foldHash(PoseidonParams params, BigInteger... fields) {
        PoseidonJmtProfile.requireSupported(params);
        requireCanonical(fields, params.field().prime());
        return FastPoseidonBls12381T3.hashN(fields);
    }

    static BigInteger compress(PoseidonParams params, BigInteger domain, BigInteger left, BigInteger right) {
        PoseidonJmtProfile.requireSupported(params);
        requireCanonical(new BigInteger[]{domain, left, right}, params.field().prime());
        return FastPoseidonBls12381T3.spongeHash(domain, left, right);
    }

    static BigInteger unsigned(byte[] bytes) {
        return bytes.length == 0 ? BigInteger.ZERO : new BigInteger(1, bytes);
    }

    private static void requireCanonical(BigInteger[] fields, BigInteger prime) {
        Objects.requireNonNull(fields, "fields");
        for (int i = 0; i < fields.length; i++) {
            BigInteger field = Objects.requireNonNull(fields[i], "fields[" + i + "]");
            if (field.signum() < 0 || field.compareTo(prime) >= 0) {
                throw new IllegalArgumentException("non-canonical field at index " + i);
            }
        }
    }

    private static List<BigInteger> fixedChunks(byte[] input) {
        int chunksRequired = (input.length + PoseidonJmtProfile.DIGEST_BYTES - 1)
                / PoseidonJmtProfile.DIGEST_BYTES;
        if (chunksRequired > PoseidonJmtProfile.FIXED_DIGEST_CHUNKS) return null;
        List<BigInteger> chunks = new ArrayList<>();
        int offset = 0;
        int remainder = input.length % PoseidonJmtProfile.DIGEST_BYTES;
        if (remainder != 0) {
            chunks.add(unsigned(Arrays.copyOfRange(input, 0, remainder)));
            offset = remainder;
        }
        while (offset < input.length) {
            BigInteger chunk = unsigned(Arrays.copyOfRange(
                    input, offset, offset + PoseidonJmtProfile.DIGEST_BYTES));
            if (chunk.compareTo(PRIME) >= 0) return null;
            chunks.add(chunk);
            offset += PoseidonJmtProfile.DIGEST_BYTES;
        }
        return chunks.size() <= PoseidonJmtProfile.FIXED_DIGEST_CHUNKS ? List.copyOf(chunks) : null;
    }
}
