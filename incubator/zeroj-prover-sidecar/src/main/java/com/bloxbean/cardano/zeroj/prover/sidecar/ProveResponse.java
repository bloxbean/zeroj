package com.bloxbean.cardano.zeroj.prover.sidecar;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Response from the prover sidecar after successful proof generation.
 *
 * @param proofJson      the snarkjs proof.json content
 * @param publicSignals  the public signals (snarkjs public.json content)
 * @param protocol       proof system (e.g., "groth16")
 * @param curve          curve (e.g., "bn128", "bls12381")
 * @param provingTimeMs  time spent proving in milliseconds
 */
public record ProveResponse(
        String proofJson,
        List<BigInteger> publicSignals,
        String protocol,
        String curve,
        long provingTimeMs
) {

    public ProveResponse {
        Objects.requireNonNull(proofJson, "proofJson required");
        Objects.requireNonNull(publicSignals, "publicSignals required");
        Objects.requireNonNull(protocol, "protocol required");
        Objects.requireNonNull(curve, "curve required");
        publicSignals = List.copyOf(publicSignals);
    }
}
