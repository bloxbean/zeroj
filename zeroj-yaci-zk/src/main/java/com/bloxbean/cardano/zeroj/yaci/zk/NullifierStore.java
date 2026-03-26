package com.bloxbean.cardano.zeroj.yaci.zk;

/**
 * Tracks used nullifiers to prevent double-spend.
 */
public interface NullifierStore {

    /**
     * Check if a nullifier has been used.
     */
    boolean isUsed(byte[] nullifier);

    /**
     * Mark a nullifier as used. Returns false if it was already used (atomic check-and-set).
     */
    boolean markUsed(byte[] nullifier);
}
