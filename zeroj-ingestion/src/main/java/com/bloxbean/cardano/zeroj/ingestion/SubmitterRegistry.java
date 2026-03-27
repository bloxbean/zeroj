package com.bloxbean.cardano.zeroj.ingestion;

import java.security.PublicKey;
import java.util.Optional;

/**
 * Registry of authorized submitters and their Ed25519 public keys.
 */
public interface SubmitterRegistry {

    /**
     * Look up a submitter's public key.
     *
     * @return the public key, or empty if the submitter is not registered
     */
    Optional<PublicKey> getPublicKey(String submitterId);

    /**
     * Check if a submitter is authorized to submit for a given app.
     */
    boolean isAuthorized(String submitterId, String appId);

    /**
     * Register a submitter with their public key and authorized app(s).
     */
    void register(String submitterId, PublicKey publicKey, String... authorizedApps);
}
