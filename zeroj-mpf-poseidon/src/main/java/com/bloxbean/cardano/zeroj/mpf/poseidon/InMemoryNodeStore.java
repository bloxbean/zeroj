package com.bloxbean.cardano.zeroj.mpf.poseidon;

import com.bloxbean.cardano.vds.core.api.NodeStore;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Small public in-memory CCL {@link NodeStore} for examples and tests.
 */
public final class InMemoryNodeStore implements NodeStore {
    private final Map<Key, byte[]> values = new ConcurrentHashMap<>();

    @Override
    public byte[] get(byte[] hash) {
        byte[] value = values.get(new Key(hash));
        return value == null ? null : Arrays.copyOf(value, value.length);
    }

    @Override
    public void put(byte[] hash, byte[] nodeBytes) {
        values.put(new Key(hash), Arrays.copyOf(nodeBytes, nodeBytes.length));
    }

    @Override
    public void delete(byte[] hash) {
        values.remove(new Key(hash));
    }

    public void clear() {
        values.clear();
    }

    private record Key(byte[] bytes) {
        private Key {
            bytes = bytes == null ? null : Arrays.copyOf(bytes, bytes.length);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Key key && Arrays.equals(bytes, key.bytes);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(bytes);
        }
    }
}
