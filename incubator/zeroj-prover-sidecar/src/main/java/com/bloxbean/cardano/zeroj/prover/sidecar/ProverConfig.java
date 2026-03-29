package com.bloxbean.cardano.zeroj.prover.sidecar;

import java.time.Duration;
import java.util.Objects;

/**
 * Configuration for the prover sidecar client.
 *
 * @param baseUrl         sidecar HTTP base URL (e.g., "http://localhost:3000")
 * @param connectTimeout  connection timeout
 * @param proveTimeout    proving request timeout (proving can be slow)
 * @param maxRetries      maximum retry attempts for transient failures
 * @param retryDelay      initial delay between retries (doubles on each retry)
 */
public record ProverConfig(
        String baseUrl,
        Duration connectTimeout,
        Duration proveTimeout,
        int maxRetries,
        Duration retryDelay
) {

    public ProverConfig {
        Objects.requireNonNull(baseUrl, "baseUrl required");
        Objects.requireNonNull(connectTimeout, "connectTimeout required");
        Objects.requireNonNull(proveTimeout, "proveTimeout required");
        Objects.requireNonNull(retryDelay, "retryDelay required");
        if (maxRetries < 0) throw new IllegalArgumentException("maxRetries must be >= 0");
    }

    /**
     * Default config for local development (localhost:3000, 30s prove timeout, 2 retries).
     */
    public static ProverConfig localhost() {
        return new ProverConfig(
                "http://localhost:3000",
                Duration.ofSeconds(5),
                Duration.ofSeconds(30),
                2,
                Duration.ofMillis(500)
        );
    }

    /**
     * Config builder for custom setups.
     */
    public static ProverConfig of(String baseUrl) {
        return new ProverConfig(
                baseUrl,
                Duration.ofSeconds(5),
                Duration.ofSeconds(60),
                3,
                Duration.ofSeconds(1)
        );
    }
}
