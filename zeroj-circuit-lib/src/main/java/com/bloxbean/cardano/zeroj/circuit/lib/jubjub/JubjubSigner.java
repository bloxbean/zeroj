package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

/**
 * Explicit Jubjub signing boundary. Implementations define their assurance profile,
 * concurrency behavior, key ownership, and close semantics.
 */
public interface JubjubSigner extends AutoCloseable {

    JubjubSigningProfile profile();

    JubjubPoint publicKey();

    /**
     * Signs one explicitly encoded public message.
     *
     * <p>Implementations supplied by ZeroJ are safe for concurrent calls. Hardened
     * implementations allocate operation-owned scratch and auxiliary-randomness storage for
     * each admitted call; no secret-bearing scratch is shared between calls. Hedged profiles
     * are intentionally nondeterministic. Once close starts, no new operation is admitted;
     * an operation admitted first may finish under the close contract below.
     *
     * @throws IllegalStateException if this signer is closing or closed
     */
    EdDSAJubjub.Signature sign(JubjubMessage message);

    /**
     * Closes the signer and its owned key material. New signing calls fail; profile and public
     * key metadata remain available. Already-admitted hardened operations finish before the
     * key is wiped. Every concurrent or subsequent close waits for destruction completion and
     * observes the same close failure, if any.
     */
    @Override
    void close();
}
