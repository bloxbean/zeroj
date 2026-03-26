package com.bloxbean.cardano.zeroj.api;

import java.util.Objects;

/**
 * Typed identifier for a ZK circuit.
 *
 * <p>A circuit id is a unique, opaque string identifying the circuit that produced a proof.
 * This is used to look up the correct verification key and to enforce circuit allowlists.</p>
 *
 * @param value the circuit identifier string (must not be null or blank)
 */
public record CircuitId(String value) {

    public CircuitId {
        Objects.requireNonNull(value, "circuit id must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("circuit id must not be blank");
        }
    }

    @Override
    public String toString() {
        return value;
    }
}
