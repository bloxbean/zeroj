package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParams;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Canonical Poseidon byte digest used by the Poseidon-rooted MPF profile.
 */
public final class PoseidonMpfHash {
    /** Commitment profile written to persistent-store manifests. */
    public static final String PROFILE_ID = "zeroj-poseidon-mpf-v2";
    public static final int DIGEST_LENGTH = 32;
    public static final int KEY_PATH_NIBBLES = DIGEST_LENGTH * 2;
    public static final int MAX_DIGEST_CHUNKS = 3;
    public static final int RAW_BYTES_PER_CHUNK = 31;

    static final BigInteger DOMAIN_BYTES = BigInteger.valueOf(0x5a4d5046L); // ZMPF
    static final BigInteger DOMAIN_LEAF = BigInteger.valueOf(0x5a4d5047L);
    static final BigInteger DOMAIN_KEY_PATH = BigInteger.valueOf(0x5a4d5048L);
    static final BigInteger DOMAIN_KEY_NULLIFIER = BigInteger.valueOf(0x5a4d5049L);
    static final BigInteger DOMAIN_RAW_BYTES_V2 = BigInteger.valueOf(0x5a4d504aL);

    private static final BigInteger PRIME = FieldConfig.BLS12_381.prime();

    private PoseidonMpfHash() {}

    public static byte[] digest(byte[] bytes) {
        return digest(PoseidonParamsBLS12_381T3.INSTANCE, bytes);
    }

    public static byte[] digest(PoseidonParams params, byte[] bytes) {
        return toDigestBytes(digestField(params, bytes));
    }

    public static BigInteger digestField(PoseidonParams params, byte[] bytes) {
        requireBlsParams(params);
        Objects.requireNonNull(bytes, "bytes");

        List<BigInteger> chunks = circuitCompatibleChunks(bytes);
        if (chunks != null) {
            List<BigInteger> fields = new ArrayList<>(2 + MAX_DIGEST_CHUNKS);
            fields.add(DOMAIN_BYTES);
            fields.add(BigInteger.valueOf(bytes.length));
            fields.addAll(chunks);
            while (fields.size() < 2 + MAX_DIGEST_CHUNKS) {
                fields.add(BigInteger.ZERO);
            }
            return hashFields(params, fields.toArray(BigInteger[]::new));
        }

        // CCL's HashFunction contract accepts arbitrary bytes. The internal MPF
        // strings mirrored by ZkMpf always take the fixed path above, while raw
        // keys/values that are not canonical scalar chunks use an injective,
        // domain-separated 31-byte encoding. Every such chunk is < 2^248 and
        // therefore a canonical BLS12-381 scalar field element.
        List<BigInteger> fields = new ArrayList<>(2 + ((bytes.length + RAW_BYTES_PER_CHUNK - 1)
                / RAW_BYTES_PER_CHUNK));
        fields.add(DOMAIN_RAW_BYTES_V2);
        fields.add(BigInteger.valueOf(bytes.length));
        for (int offset = 0; offset < bytes.length; offset += RAW_BYTES_PER_CHUNK) {
            int end = Math.min(bytes.length, offset + RAW_BYTES_PER_CHUNK);
            fields.add(unsigned(Arrays.copyOfRange(bytes, offset, end)));
        }
        return hashFields(params, fields.toArray(BigInteger[]::new));
    }

    /**
     * Returns the fixed circuit-compatible chunks, or {@code null} when the
     * total raw-byte fallback must be used.
     */
    private static List<BigInteger> circuitCompatibleChunks(byte[] bytes) {
        List<BigInteger> chunks = new ArrayList<>();

        int offset = 0;
        int remainder = bytes.length % DIGEST_LENGTH;
        if (remainder != 0) {
            chunks.add(unsigned(Arrays.copyOfRange(bytes, 0, remainder)));
            offset = remainder;
        }

        while (offset < bytes.length) {
            BigInteger chunk = unsigned(Arrays.copyOfRange(bytes, offset, offset + DIGEST_LENGTH));
            if (chunk.compareTo(PRIME) >= 0) {
                return null;
            }
            chunks.add(chunk);
            offset += DIGEST_LENGTH;
        }
        if (chunks.size() > MAX_DIGEST_CHUNKS) {
            return null;
        }
        return chunks;
    }

    public static BigInteger fieldFromDigestBytes(byte[] digest) {
        Objects.requireNonNull(digest, "digest");
        if (digest.length != DIGEST_LENGTH) {
            throw new IllegalArgumentException("digest must be 32 bytes, got " + digest.length);
        }
        BigInteger value = unsigned(digest);
        if (value.compareTo(PRIME) >= 0) {
            throw new IllegalArgumentException("digest is not a canonical BLS12-381 scalar field element");
        }
        return value;
    }

    /**
     * Hashes two canonical MPF digests through the exact fixed 64-byte profile
     * without allocating and reparsing a temporary {@code left || right} array.
     */
    static byte[] digestPair(PoseidonParams params, byte[] left, byte[] right) {
        BigInteger leftField = fieldFromDigestBytes(left);
        BigInteger rightField = fieldFromDigestBytes(right);
        return toDigestBytes(hashFields(params,
                DOMAIN_BYTES,
                BigInteger.valueOf(DIGEST_LENGTH * 2L),
                leftField,
                rightField,
                BigInteger.ZERO));
    }

    public static byte[] toDigestBytes(BigInteger value) {
        Objects.requireNonNull(value, "value");
        BigInteger normalized = value.mod(PRIME);
        byte[] raw = normalized.toByteArray();
        byte[] out = new byte[DIGEST_LENGTH];
        int src = Math.max(0, raw.length - DIGEST_LENGTH);
        int count = Math.min(raw.length, DIGEST_LENGTH);
        System.arraycopy(raw, src, out, DIGEST_LENGTH - count, count);
        return out;
    }

    public static int[] digestToNibbles(byte[] digest) {
        Objects.requireNonNull(digest, "digest");
        if (digest.length != DIGEST_LENGTH) {
            throw new IllegalArgumentException("digest must be 32 bytes, got " + digest.length);
        }
        int[] nibbles = new int[KEY_PATH_NIBBLES];
        for (int i = 0; i < digest.length; i++) {
            int b = digest[i] & 0xff;
            nibbles[i * 2] = (b >>> 4) & 0x0f;
            nibbles[i * 2 + 1] = b & 0x0f;
        }
        return nibbles;
    }

    public static BigInteger keyPathCommitment(PoseidonParams params, int[] keyPath) {
        return hashKeyPath(params, DOMAIN_KEY_PATH, keyPath);
    }

    public static BigInteger keyPathNullifier(PoseidonParams params, int[] keyPath) {
        return hashKeyPath(params, DOMAIN_KEY_NULLIFIER, keyPath);
    }

    public static void requireBlsParams(PoseidonParams params) {
        Objects.requireNonNull(params, "params");
        if (!FieldConfig.BLS12_381.equals(params.field())) {
            throw new IllegalArgumentException("Poseidon MPF requires BLS12-381 Poseidon params");
        }
        if (params.t() != 3 || params.alpha() != 5) {
            throw new IllegalArgumentException("Poseidon MPF supports only t=3, alpha=5 params");
        }
    }

    static BigInteger unsigned(byte[] bytes) {
        return bytes.length == 0 ? BigInteger.ZERO : new BigInteger(1, bytes);
    }

    private static BigInteger hashKeyPath(PoseidonParams params, BigInteger domain, int[] keyPath) {
        requireBlsParams(params);
        Objects.requireNonNull(keyPath, "keyPath");
        if (keyPath.length != KEY_PATH_NIBBLES) {
            throw new IllegalArgumentException("keyPath must contain 64 nibbles, got " + keyPath.length);
        }
        BigInteger[] fields = new BigInteger[2 + keyPath.length];
        fields[0] = domain;
        fields[1] = BigInteger.valueOf(keyPath.length);
        for (int i = 0; i < keyPath.length; i++) {
            int nibble = keyPath[i];
            if (nibble < 0 || nibble > 15) {
                throw new IllegalArgumentException("keyPath nibble out of range at " + i + ": " + nibble);
            }
            fields[i + 2] = BigInteger.valueOf(nibble);
        }
        return hashFields(params, fields);
    }

    static BigInteger hashFields(PoseidonParams params, BigInteger... fields) {
        if (PoseidonParamsBLS12_381T3.INSTANCE.equals(params)) {
            return PoseidonMpfFastPoseidon.hashN(fields);
        }
        return PoseidonHash.hashN(params, fields);
    }
}
