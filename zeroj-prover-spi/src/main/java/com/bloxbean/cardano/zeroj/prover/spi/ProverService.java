package com.bloxbean.cardano.zeroj.prover.spi;

/**
 * Contract for a ZK proof generation backend.
 *
 * <p>Implementations may be backed by a local native prover, a pure Java prover,
 * or a remote proving service.</p>
 */
public interface ProverService {

    /**
     * Generate a proof for the given request.
     *
     * @param request the proving request
     * @return the prove response with proof bytes/JSON and public signals
     * @throws ProverException if proving fails
     */
    ProveResponse prove(ProveRequest request);
}
