package com.bloxbean.cardano.zeroj.yaci.zk;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link CircuitAllowlist}.
 */
public class InMemoryCircuitAllowlist implements CircuitAllowlist {

    // key = "circuitId:version", value = true (allowed) or absent (retired/unknown)
    private final Set<String> allowed = ConcurrentHashMap.newKeySet();
    private final Set<String> retired = ConcurrentHashMap.newKeySet();

    @Override
    public boolean isAllowed(String circuitId, String version) {
        var key = circuitId + ":" + version;
        return allowed.contains(key) && !retired.contains(key);
    }

    @Override
    public void allow(String circuitId, String version) {
        allowed.add(circuitId + ":" + version);
    }

    @Override
    public void retire(String circuitId, String version) {
        retired.add(circuitId + ":" + version);
    }
}
