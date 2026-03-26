package com.bloxbean.cardano.zeroj.yaci.zk;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link CircuitRegistry}.
 */
public class InMemoryCircuitRegistry implements CircuitRegistry {

    private final Map<String, CircuitVersionInfo> registry = new ConcurrentHashMap<>();

    private static String key(String circuitId, String version) {
        return circuitId + ":" + version;
    }

    @Override
    public void register(CircuitVersionInfo info) {
        registry.put(key(info.circuitId(), info.version()), info);
    }

    @Override
    public void deprecate(String circuitId, String version, Instant deadline,
                          String successorId, String successorVersion) {
        var key = key(circuitId, version);
        var existing = registry.get(key);
        if (existing == null) return;

        registry.put(key, new CircuitVersionInfo(
                circuitId, version, CircuitRegistry.Lifecycle.DEPRECATED,
                existing.registeredAt(), Instant.now(), deadline, null,
                successorId, successorVersion));
    }

    @Override
    public void retire(String circuitId, String version) {
        var key = key(circuitId, version);
        var existing = registry.get(key);
        if (existing == null) return;

        registry.put(key, new CircuitVersionInfo(
                circuitId, version, CircuitRegistry.Lifecycle.RETIRED,
                existing.registeredAt(), existing.deprecatedAt(),
                existing.deprecationDeadline(), Instant.now(),
                existing.successorCircuitId(), existing.successorVersion()));
    }

    @Override
    public Optional<CircuitVersionInfo> getInfo(String circuitId, String version) {
        return Optional.ofNullable(registry.get(key(circuitId, version)));
    }

    @Override
    public List<CircuitVersionInfo> listVersions(String circuitId) {
        return registry.values().stream()
                .filter(info -> info.circuitId().equals(circuitId))
                .toList();
    }

    // --- CircuitAllowlist compatibility ---

    @Override
    public boolean isAllowed(String circuitId, String version) {
        var info = registry.get(key(circuitId, version));
        if (info == null) return false;
        return info.acceptsSubmissionsAt(Instant.now());
    }

    @Override
    public void allow(String circuitId, String version) {
        register(CircuitVersionInfo.active(circuitId, version));
    }
}
