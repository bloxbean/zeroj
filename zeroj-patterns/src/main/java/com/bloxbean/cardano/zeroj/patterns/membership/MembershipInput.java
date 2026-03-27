package com.bloxbean.cardano.zeroj.patterns.membership;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Input data for a membership proof — bridges domain concepts to the proof layer.
 * <p>
 * Captures the set commitment (Merkle root) and constraint outputs before proof generation.
 * Once a proof is obtained, call {@link #withProof} to produce a {@link MembershipProof}
 * ready for verification.
 * <p>
 * Example:
 * <pre>{@code
 * // 1. Prepare membership input
 * var input = MembershipInput.of(merkleRoot, List.of(threshold));
 *
 * // 2. Generate proof (proving leaf inclusion + constraint)
 * byte[] proofBytes = prover.prove(leaf, merklePath, constraintWitness);
 *
 * // 3. Create typed proof for verification
 * MembershipProof proof = input.withProof(proofBytes, "whitelist");
 * var result = verifier.verifyMembership(proof, expectedRoot, material);
 * }</pre>
 *
 * @param merkleRoot        the root of the Merkle tree (commitment to the set)
 * @param constraintOutputs public outputs from constraint evaluation
 */
public record MembershipInput(
        byte[] merkleRoot,
        List<BigInteger> constraintOutputs
) {

    public MembershipInput {
        Objects.requireNonNull(merkleRoot, "merkleRoot required");
        if (merkleRoot.length == 0) throw new IllegalArgumentException("merkleRoot must not be empty");
        merkleRoot = merkleRoot.clone();
        constraintOutputs = constraintOutputs != null ? List.copyOf(constraintOutputs) : List.of();
    }

    @Override public byte[] merkleRoot() { return merkleRoot.clone(); }

    /**
     * Create input from Merkle root and constraint outputs.
     */
    public static MembershipInput of(byte[] merkleRoot, List<BigInteger> constraintOutputs) {
        return new MembershipInput(merkleRoot, constraintOutputs);
    }

    /**
     * Attach a proof to produce a {@link MembershipProof} ready for verification.
     */
    public MembershipProof withProof(byte[] proofBytes, String circuitId) {
        return withProof(proofBytes, circuitId, ProofSystemId.GROTH16, CurveId.BN254);
    }

    /**
     * Attach a proof with explicit proof system and curve.
     */
    public MembershipProof withProof(byte[] proofBytes, String circuitId,
                                      ProofSystemId proofSystem, CurveId curve) {
        return MembershipProof.builder()
                .merkleRoot(merkleRoot)
                .constraintOutputs(constraintOutputs)
                .proofBytes(proofBytes)
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .build();
    }
}
