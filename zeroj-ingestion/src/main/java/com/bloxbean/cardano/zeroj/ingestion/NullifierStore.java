package com.bloxbean.cardano.zeroj.ingestion;

/**
 * Tracks used nullifiers to prevent double-spend.
 */
public interface NullifierStore {

    /**
     * Check if a nullifier has been used (global scope).
     */
    boolean isUsed(byte[] nullifier);

    /**
     * Mark a nullifier as used (global scope). Returns false if it was already used (atomic check-and-set).
     */
    boolean markUsed(byte[] nullifier);

    /**
     * Check if a nullifier has been used within a specific app scope.
     * App-scoped nullifiers are independent: the same nullifier bytes can be used
     * in different apps without conflict.
     */
    default boolean isUsed(String appId, byte[] nullifier) {
        return isUsed(nullifier);
    }

    /**
     * Mark a nullifier as used within a specific app scope. Returns false if already used.
     */
    default boolean markUsed(String appId, byte[] nullifier) {
        return markUsed(nullifier);
    }
}
