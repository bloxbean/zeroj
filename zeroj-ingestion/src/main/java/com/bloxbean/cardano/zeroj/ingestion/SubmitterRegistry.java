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

    /**
     * Check if a submitter is active (not suspended or revoked).
     * Default returns true for backward compatibility.
     */
    default boolean isActive(String submitterId) {
        return getPublicKey(submitterId).isPresent();
    }

    /**
     * Revoke a submitter permanently. Revoked submitters cannot be reinstated.
     */
    default void revoke(String submitterId) {
        // no-op default for backward compatibility
    }

    /**
     * Suspend a submitter temporarily. Can be reinstated later.
     */
    default void suspend(String submitterId) {
        // no-op default for backward compatibility
    }

    /**
     * Reinstate a previously suspended submitter back to ACTIVE.
     * Has no effect on REVOKED submitters.
     */
    default void reinstate(String submitterId) {
        // no-op default for backward compatibility
    }

    /**
     * Rotate the submitter's public key.
     *
     * @return true if the key was rotated, false if the submitter does not exist or is not active
     */
    default boolean rotateKey(String submitterId, PublicKey newPublicKey) {
        // no-op default for backward compatibility
        return false;
    }

    /**
     * Submitter lifecycle status.
     */
    enum SubmitterStatus {
        ACTIVE,
        SUSPENDED,
        REVOKED
    }
}
