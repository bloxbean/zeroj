package com.bloxbean.cardano.zeroj.jmt.load;

import java.nio.ByteBuffer;

/** Streaming deterministic dataset with unique keys and bounded batch allocation. */
public final class DeterministicJmtDataset {
    public static final String SCHEMA_ID = "zeroj-poseidon-jmt-load-v1";
    public static final int KEY_BYTES = 24;
    public static final int VALUE_BYTES = 32;

    private static final int KEY_MAGIC = 0x5a4a4d4b; // ZJMK
    private static final int VALUE_MAGIC = 0x5a4a4d56; // ZJMV

    private DeterministicJmtDataset() {}

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
        byte[] value = ByteBuffer.allocate(VALUE_BYTES)
                .putLong(mix64(seed ^ index))
                .putLong(mix64(seed + index))
                .putLong(index)
                .putInt(VALUE_MAGIC)
                .putInt(1)
                .array();
        value[0] = (byte) 0xff; // exercises the total raw-byte hash path
        return value;
    }

    private static long mix64(long value) {
        long mixed = value + 0x9e3779b97f4a7c15L;
        mixed = (mixed ^ (mixed >>> 30)) * 0xbf58476d1ce4e5b9L;
        mixed = (mixed ^ (mixed >>> 27)) * 0x94d049bb133111ebL;
        return mixed ^ (mixed >>> 31);
    }

    private static void requireIndex(long index) {
        if (index < 0) throw new IllegalArgumentException("index must be >= 0");
    }
}
