package com.bloxbean.cardano.zeroj.crypto.groth16;

/**
 * Complete data from a parsed .zkey file: proving key + R1CS constraints.
 *
 * <p>Both are needed for proof generation — the proving key provides the trusted
 * setup points, and the constraints define the R1CS system used by h(x) computation.</p>
 */
public record ZkeyData(
        Groth16ProvingKey provingKey,
        Groth16Prover.R1CSConstraint[] constraints,
        int numConstraints,
        int numWires,
        int domainSize
) {}
