package com.bloxbean.cardano.zeroj.prover.sidecar;

import com.bloxbean.cardano.zeroj.api.ZkProofEnvelope;

import java.util.List;

/**
 * Contract for a ZK proof generation service.
 *
 * <p>Implementations may be backed by a Docker sidecar (snarkjs), a remote
 * proving service, or a local native prover. The output is always a standard
 * {@link ZkProofEnvelope} compatible with ZeroJ verifiers.</p>
 */
public interface ProverService {

    /**
     * Generate a proof for the given request.
     *
     * @param request the proving request (circuit name + inputs)
     * @return the prove response with proof JSON and public signals
     * @throws ProverException if proving fails
     */
    ProveResponse prove(ProveRequest request);

    /**
     * Generate a proof and wrap it as a {@link ZkProofEnvelope}.
     *
     * @param request   the proving request
     * @param circuitId the circuit identifier for the envelope
     * @return a fully populated proof envelope ready for verification
     * @throws ProverException if proving fails
     */
    ZkProofEnvelope proveAndWrap(ProveRequest request, String circuitId);

    /**
     * Check if the sidecar is healthy and reachable.
     *
     * @return true if the sidecar responds to health checks
     */
    boolean isHealthy();

    /**
     * List circuits available in the sidecar.
     *
     * @return list of circuit names
     */
    List<String> listCircuits();
}
