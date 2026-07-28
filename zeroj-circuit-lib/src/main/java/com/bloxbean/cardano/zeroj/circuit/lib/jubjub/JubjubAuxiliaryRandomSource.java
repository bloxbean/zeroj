package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * Internal fixed-size randomness boundary for hedged-candidate validation.
 *
 * <p>A future validated implementation must own a bounded, non-reentrant source whose
 * provider and lifecycle are part of the approved platform profile. The source must not
 * retain the caller's output buffer. Closing releases or wipes provider-owned state where
 * the provider supports it. Neither {@link #fill(byte[])} nor {@link #close()} may call back
 * into the owning signer, including its {@code close}: signer close waits for admitted
 * operations and source destruction, so such re-entry violates the provider contract.
 */
@FunctionalInterface
interface JubjubAuxiliaryRandomSource extends AutoCloseable {
    void fill(byte[] output);

    @Override
    default void close() {
        // Stateless test adapters have nothing to release.
    }
}
