package com.bloxbean.cardano.zeroj.crypto.groth16;

import com.bloxbean.cardano.zeroj.api.R1CSConstraint;

import java.util.List;

/**
 * Complete data from a parsed .zkey file: proving key + R1CS constraints.
 *
 * <p>Both are needed for proof generation — the proving key provides the trusted
 * setup points, and the constraints define the R1CS system used by h(x) computation.</p>
 */
public record ZkeyData(
        Groth16ProvingKey provingKey,
        List<R1CSConstraint> constraints,
        int numConstraints,
        int numWires,
        int domainSize
) {}
