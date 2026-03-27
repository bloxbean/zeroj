package com.bloxbean.cardano.zeroj.ingestion;

import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link SubmitterRegistry}.
 */
public class InMemorySubmitterRegistry implements SubmitterRegistry {

    private final Map<String, PublicKey> keys = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> authorizations = new ConcurrentHashMap<>();

    @Override
    public Optional<PublicKey> getPublicKey(String submitterId) {
        return Optional.ofNullable(keys.get(submitterId));
    }

    @Override
    public boolean isAuthorized(String submitterId, String appId) {
        var apps = authorizations.get(submitterId);
        return apps != null && apps.contains(appId);
    }

    @Override
    public void register(String submitterId, PublicKey publicKey, String... authorizedApps) {
        keys.put(submitterId, publicKey);
        var apps = authorizations.computeIfAbsent(submitterId, k -> ConcurrentHashMap.newKeySet());
        apps.addAll(Arrays.asList(authorizedApps));
    }
}
