package com.bloxbean.cardano.zeroj.yaci.zk;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link StateRootStore}.
 */
public class InMemoryStateRootStore implements StateRootStore {

    private final Map<String, byte[]> roots = new ConcurrentHashMap<>();

    @Override
    public byte[] getCurrentRoot(String appId) {
        var root = roots.get(appId);
        return root != null ? root.clone() : null;
    }

    @Override
    public void updateRoot(String appId, byte[] newRoot) {
        roots.put(appId, newRoot.clone());
    }

    /**
     * Initialize the state root for an app (for bootstrapping).
     */
    public void initialize(String appId, byte[] genesisRoot) {
        roots.putIfAbsent(appId, genesisRoot.clone());
    }
}
