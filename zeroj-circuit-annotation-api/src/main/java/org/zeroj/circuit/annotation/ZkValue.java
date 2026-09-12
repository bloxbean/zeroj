package org.zeroj.circuit.annotation;

import org.zeroj.circuit.Signal;

import java.util.List;

/**
 * Base contract for symbolic circuit values.
 */
public interface ZkValue {

    /**
     * Flatten this symbolic value into the backing circuit signals.
     */
    List<Signal> signals();

    /**
     * Add type-specific constraints. Implementations make this idempotent where
     * they add constraints eagerly during public/secret input construction.
     */
    void assertWellFormed();
}
