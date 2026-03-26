package com.bloxbean.cardano.zeroj.yaci.zk;

import java.nio.ByteBuffer;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link NullifierStore}.
 */
public class InMemoryNullifierStore implements NullifierStore {

    private final Set<ByteBuffer> used = ConcurrentHashMap.newKeySet();

    @Override
    public boolean isUsed(byte[] nullifier) {
        return used.contains(ByteBuffer.wrap(nullifier));
    }

    @Override
    public boolean markUsed(byte[] nullifier) {
        return used.add(ByteBuffer.wrap(nullifier.clone()));
    }
}
