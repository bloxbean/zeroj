package com.bloxbean.cardano.zeroj.prover.spi;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Response from a proof generation backend.
 *
 * @param proofJson      proof JSON content
 * @param publicSignals  public signals
 * @param protocol       proof system (for example, {@code groth16})
 * @param curve          curve (for example, {@code bls12381})
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
