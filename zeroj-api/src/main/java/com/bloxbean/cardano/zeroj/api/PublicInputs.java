package com.bloxbean.cardano.zeroj.api;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Typed wrapper over a list of public input field elements.
 *
 * <p>Public inputs are the values visible to both prover and verifier.
 * They are represented as {@link BigInteger} field elements.</p>
 *
 * @param values the public input field elements (immutable, must not be null or empty)
 */
public record PublicInputs(List<BigInteger> values) {

    public PublicInputs {
        Objects.requireNonNull(values, "public inputs must not be null");
        values = List.copyOf(values); // defensive immutable copy
    }

    /**
     * Number of public inputs.
     */
    public int size() {
        return values.size();
    }

    /**
     * Get the public input at the given index.
     */
    public BigInteger get(int index) {
        return values.get(index);
    }
}
