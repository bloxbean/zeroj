package com.bloxbean.cardano.zeroj.ingestion;

import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory implementation of {@link SubmitterRegistry} with status tracking.
 */
public class InMemorySubmitterRegistry implements SubmitterRegistry {

    private final Map<String, PublicKey> keys = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> authorizations = new ConcurrentHashMap<>();
    private final Map<String, SubmitterStatus> statuses = new ConcurrentHashMap<>();

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
        statuses.put(submitterId, SubmitterStatus.ACTIVE);
        var apps = authorizations.computeIfAbsent(submitterId, k -> ConcurrentHashMap.newKeySet());
        apps.addAll(Arrays.asList(authorizedApps));
    }

    @Override
    public boolean isActive(String submitterId) {
        return statuses.get(submitterId) == SubmitterStatus.ACTIVE;
    }

    @Override
    public void revoke(String submitterId) {
        if (statuses.containsKey(submitterId)) {
            statuses.put(submitterId, SubmitterStatus.REVOKED);
        }
    }

    @Override
    public void suspend(String submitterId) {
        if (statuses.get(submitterId) == SubmitterStatus.ACTIVE) {
            statuses.put(submitterId, SubmitterStatus.SUSPENDED);
        }
    }

    @Override
    public void reinstate(String submitterId) {
        if (statuses.get(submitterId) == SubmitterStatus.SUSPENDED) {
            statuses.put(submitterId, SubmitterStatus.ACTIVE);
        }
    }

    @Override
    public boolean rotateKey(String submitterId, PublicKey newPublicKey) {
        if (statuses.get(submitterId) != SubmitterStatus.ACTIVE) return false;
        keys.put(submitterId, newPublicKey);
        return true;
    }

    /**
     * Get the current status of a submitter (for testing/inspection).
     */
    public SubmitterStatus getStatus(String submitterId) {
        return statuses.get(submitterId);
    }
}
