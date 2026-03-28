package com.bloxbean.cardano.zeroj.circuit;

/**
 * Functional interface for defining a circuit's constraints.
 *
 * <p>Users implement this as a lambda passed to {@link CircuitBuilder#define(CircuitDefinition)}.</p>
 */
@FunctionalInterface
public interface CircuitDefinition {

    /**
     * Define the circuit constraints using the provided API.
     *
     * @param api the circuit construction API
     */
    void define(CircuitAPI api);
}
