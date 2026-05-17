package com.bloxbean.cardano.zeroj.prover.spi;

import java.util.Map;
import java.util.Objects;

/**
 * Request to generate a ZK proof.
 *
 * @param circuitName  the circuit to prove
 * @param input        the circuit input as a key-value map (public + private inputs)
 * @param provingKeyId optional proving key ID when a backend manages multiple keys
 */
public record ProveRequest(
        String circuitName,
        Map<String, String> input,
        String provingKeyId
) {

    public ProveRequest {
        Objects.requireNonNull(circuitName, "circuitName required");
        Objects.requireNonNull(input, "input required");
        if (input.isEmpty()) throw new IllegalArgumentException("input must not be empty");
        input = Map.copyOf(input);
    }

    /**
     * Create a request with the backend's default proving key.
     */
    public static ProveRequest of(String circuitName, Map<String, String> input) {
        return new ProveRequest(circuitName, input, null);
    }
}
