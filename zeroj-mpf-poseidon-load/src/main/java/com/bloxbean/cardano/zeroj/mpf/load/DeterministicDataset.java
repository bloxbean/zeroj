package com.bloxbean.cardano.zeroj.mpf.load;

import java.nio.ByteBuffer;

/** Streaming, allocation-bounded dataset whose keys are unique by construction. */
public final class DeterministicDataset {
    public static final String SCHEMA_ID = "zeroj-poseidon-mpf-load-v1";
    public static final int KEY_BYTES = 24;
    public static final int VALUE_BYTES = 32;

    private static final int KEY_MAGIC = 0x5a4d504b; // ZMPK
    private static final int VALUE_MAGIC = 0x5a4d5056; // ZMPV

    private DeterministicDataset() {}

    public static byte[] key(long seed, long index) {
        requireIndex(index);
        return ByteBuffer.allocate(KEY_BYTES)
                .putInt(KEY_MAGIC)
                .putInt(1)
                .putLong(seed)
                .putLong(index)
                .array();
    }

    public static byte[] value(long seed, long index) {
        requireIndex(index);
        byte[] out = ByteBuffer.allocate(VALUE_BYTES)
                .putLong(mix64(seed ^ index))
                .putLong(mix64(seed + index))
                .putLong(index)
                .putInt(VALUE_MAGIC)
                .putInt(1)
                .array();
        // Force this ordinary 32-byte value through the v2 raw-byte fallback.
        // The old profile rejected it as a non-canonical scalar chunk.
        out[0] = (byte) 0xff;
        return out;
    }

    private static long mix64(long value) {
        long z = value + 0x9e3779b97f4a7c15L;
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }

    private static void requireIndex(long index) {
        if (index < 0) throw new IllegalArgumentException("index must be >= 0");
    }
}
