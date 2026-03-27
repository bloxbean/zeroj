package com.bloxbean.cardano.zeroj.ingestion;

/**
 * Tracks the current accepted state root for each app.
 */
public interface StateRootStore {

    /**
     * Get the current accepted state root for an app.
     *
     * @return the current root, or null if no state has been accepted yet
     */
    byte[] getCurrentRoot(String appId);

    /**
     * Update the state root after a successful submission.
     */
    void updateRoot(String appId, byte[] newRoot);
}
