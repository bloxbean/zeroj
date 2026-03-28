package com.bloxbean.cardano.zeroj.ingestion;

import java.nio.ByteBuffer;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link NullifierStore} with app-scoped support.
 */
public class InMemoryNullifierStore implements NullifierStore {

    private final Set<ByteBuffer> used = ConcurrentHashMap.newKeySet();
    private final Set<String> scopedUsed = ConcurrentHashMap.newKeySet();

    @Override
    public boolean isUsed(byte[] nullifier) {
        return used.contains(ByteBuffer.wrap(nullifier));
    }

    @Override
    public boolean markUsed(byte[] nullifier) {
        return used.add(ByteBuffer.wrap(nullifier.clone()));
    }

    @Override
    public boolean isUsed(String appId, byte[] nullifier) {
        return scopedUsed.contains(scopedKey(appId, nullifier));
    }

    @Override
    public boolean markUsed(String appId, byte[] nullifier) {
        return scopedUsed.add(scopedKey(appId, nullifier));
    }

    private static String scopedKey(String appId, byte[] nullifier) {
        var sb = new StringBuilder(appId).append(':');
        for (byte b : nullifier) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
