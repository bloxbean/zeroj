package com.bloxbean.cardano.zeroj.yaci.zk;

/**
 * Controls which circuit id + version combinations are allowed for submissions.
 */
public interface CircuitAllowlist {

    /**
     * Check if a circuit version is allowed (not retired, not unknown).
     */
    boolean isAllowed(String circuitId, String version);

    /**
     * Register an allowed circuit version.
     */
    void allow(String circuitId, String version);

    /**
     * Retire a circuit version (existing proofs are still valid, new submissions rejected).
     */
    void retire(String circuitId, String version);
}
