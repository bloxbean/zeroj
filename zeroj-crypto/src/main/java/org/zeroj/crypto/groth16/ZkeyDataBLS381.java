package org.zeroj.crypto.groth16;

import org.zeroj.api.R1CSConstraint;

import java.util.List;

/**
 * Complete data from a parsed BLS12-381 .zkey file: proving key + R1CS constraints.
 */
public record ZkeyDataBLS381(
        Groth16ProvingKeyBLS381 provingKey,
        List<R1CSConstraint> constraints,
        int numConstraints,
        int numWires,
        int domainSize
) {}
