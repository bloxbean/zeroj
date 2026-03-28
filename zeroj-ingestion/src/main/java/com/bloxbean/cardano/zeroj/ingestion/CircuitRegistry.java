package com.bloxbean.cardano.zeroj.ingestion;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Enhanced circuit lifecycle registry with versioning, deprecation, and retirement.
 *
 * <p>Lifecycle: ACTIVE → DEPRECATED → RETIRED</p>
 * <ul>
 *   <li><b>ACTIVE</b> — new submissions accepted</li>
 *   <li><b>DEPRECATED</b> — new submissions accepted until deprecation deadline, migration hint available</li>
 *   <li><b>RETIRED</b> — new submissions rejected</li>
 * </ul>
 *
 * <p>Implements {@link CircuitAllowlist} for backward compatibility with the pipeline.</p>
 */
public interface CircuitRegistry extends CircuitAllowlist {

    /**
     * Register a new circuit version as ACTIVE.
     */
    void register(CircuitVersionInfo info);

    /**
     * Deprecate a circuit version with a grace period and migration hint.
     *
     * @param circuitId    the circuit to deprecate
     * @param version      the version to deprecate
     * @param deadline     submissions accepted until this time
     * @param successorId  recommended successor circuit (nullable)
     * @param successorVersion recommended successor version (nullable)
     */
    void deprecate(String circuitId, String version, Instant deadline,
                   String successorId, String successorVersion);

    /**
     * Get the lifecycle info for a circuit version.
     */
    Optional<CircuitVersionInfo> getInfo(String circuitId, String version);

    /**
     * List all versions of a circuit.
     */
    List<CircuitVersionInfo> listVersions(String circuitId);

    /**
     * Validate that a migration from one circuit version to its declared successor is valid.
     * Returns true if the successor circuit is registered and ACTIVE.
     *
     * @param circuitId the circuit being deprecated
     * @param version   the version being deprecated
     * @return true if the declared successor is valid and active
     */
    default boolean validateMigration(String circuitId, String version) {
        var info = getInfo(circuitId, version);
        if (info.isEmpty()) return false;
        var cvi = info.get();
        if (cvi.successorCircuitId() == null || cvi.successorVersion() == null) return false;
        var successor = getInfo(cvi.successorCircuitId(), cvi.successorVersion());
        return successor.isPresent() && successor.get().lifecycle() == Lifecycle.ACTIVE;
    }

    /**
     * Circuit version lifecycle state.
     */
    enum Lifecycle {
        ACTIVE,
        DEPRECATED,
        RETIRED
    }

    /**
     * Full information about a circuit version.
     */
    record CircuitVersionInfo(
            String circuitId,
            String version,
            Lifecycle lifecycle,
            Instant registeredAt,
            Instant deprecatedAt,
            Instant deprecationDeadline,
            Instant retiredAt,
            String successorCircuitId,
            String successorVersion
    ) {
        public static CircuitVersionInfo active(String circuitId, String version) {
            return new CircuitVersionInfo(circuitId, version, Lifecycle.ACTIVE,
                    Instant.now(), null, null, null, null, null);
        }

        /**
         * Check if this version accepts new submissions at the given time.
         */
        public boolean acceptsSubmissionsAt(Instant now) {
            return switch (lifecycle) {
                case ACTIVE -> true;
                case DEPRECATED -> deprecationDeadline == null || now.isBefore(deprecationDeadline);
                case RETIRED -> false;
            };
        }
    }
}
