package com.bloxbean.cardano.zeroj.ingestion;

import java.time.Duration;

/**
 * Policy governing VK rotation constraints.
 *
 * @param minTransitionWindow    minimum time old VKs must remain valid after rotation
 * @param maxActiveVksPerCircuit maximum number of non-expired VKs per circuit
 * @param minTimeBetweenRotations minimum time between successive rotations for a circuit
 */
public record VkRotationPolicy(
        Duration minTransitionWindow,
        int maxActiveVksPerCircuit,
        Duration minTimeBetweenRotations
) {
    public VkRotationPolicy {
        if (minTransitionWindow == null) throw new NullPointerException("minTransitionWindow");
        if (maxActiveVksPerCircuit < 1) throw new IllegalArgumentException("maxActiveVksPerCircuit must be >= 1");
        if (minTimeBetweenRotations == null) throw new NullPointerException("minTimeBetweenRotations");
    }

    /**
     * A permissive default policy: 1-hour transition, up to 5 active VKs, no minimum between rotations.
     */
    public static VkRotationPolicy defaultPolicy() {
        return new VkRotationPolicy(Duration.ofHours(1), 5, Duration.ZERO);
    }
}
