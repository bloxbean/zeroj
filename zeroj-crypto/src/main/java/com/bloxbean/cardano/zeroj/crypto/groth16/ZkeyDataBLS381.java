package com.bloxbean.cardano.zeroj.crypto.groth16;

/**
 * Complete data from a parsed BLS12-381 .zkey file: proving key + R1CS constraints.
 */
public record ZkeyDataBLS381(
        Groth16ProvingKeyBLS381 provingKey,
        Groth16Prover.R1CSConstraint[] constraints,
        int numConstraints,
        int numWires,
        int domainSize
) {}
