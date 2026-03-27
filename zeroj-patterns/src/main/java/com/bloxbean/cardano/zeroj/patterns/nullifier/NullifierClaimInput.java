package com.bloxbean.cardano.zeroj.patterns.nullifier;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.util.List;
import java.util.Objects;

/**
 * Input data for a nullifier-guarded claim — bridges domain concepts to the proof layer.
 * <p>
 * Captures the claim parameters before proof generation. Once a proof is obtained,
 * call {@link #withProof} to produce a {@link NullifierClaim} ready for verification.
 * <p>
 * Example:
 * <pre>{@code
 * // 1. Prepare claim from domain data
 * var input = NullifierClaimInput.of(nullifierHash, commitmentRoot, claimAmount);
 *
 * // 2. Generate proof externally
 * byte[] proofBytes = prover.prove(secret, merkleProof);
 *
 * // 3. Create typed claim for verification
 * NullifierClaim claim = input.withProof(proofBytes, "airdrop-claim");
 * var result = verifier.verifyAndAccept(claim, material);
 * }</pre>
 *
 * @param nullifier             deterministic hash derived from secret (published on-chain)
 * @param commitment            commitment to the eligible set (e.g., Merkle root)
 * @param claimValue            the claimed output value (may be public or private)
 * @param additionalPublicInputs extra public values
 */
public record NullifierClaimInput(
        byte[] nullifier,
        byte[] commitment,
        BigInteger claimValue,
        List<BigInteger> additionalPublicInputs
) {

    public NullifierClaimInput {
        Objects.requireNonNull(nullifier, "nullifier required");
        Objects.requireNonNull(commitment, "commitment required");
        if (nullifier.length == 0) throw new IllegalArgumentException("nullifier must not be empty");
        if (commitment.length == 0) throw new IllegalArgumentException("commitment must not be empty");
        nullifier = nullifier.clone();
        commitment = commitment.clone();
        additionalPublicInputs = additionalPublicInputs != null ? List.copyOf(additionalPublicInputs) : List.of();
    }

    @Override public byte[] nullifier() { return nullifier.clone(); }
    @Override public byte[] commitment() { return commitment.clone(); }

    /**
     * Create input from nullifier and commitment bytes.
     */
    public static NullifierClaimInput of(byte[] nullifier, byte[] commitment, BigInteger claimValue) {
        return new NullifierClaimInput(nullifier, commitment, claimValue, List.of());
    }

    /**
     * Attach a proof to produce a {@link NullifierClaim} ready for verification.
     */
    public NullifierClaim withProof(byte[] proofBytes, String circuitId) {
        return withProof(proofBytes, circuitId, ProofSystemId.GROTH16, CurveId.BN254);
    }

    /**
     * Attach a proof with explicit proof system and curve.
     */
    public NullifierClaim withProof(byte[] proofBytes, String circuitId,
                                     ProofSystemId proofSystem, CurveId curve) {
        return NullifierClaim.builder()
                .nullifier(nullifier)
                .commitment(commitment)
                .claimValue(claimValue)
                .additionalPublicInputs(additionalPublicInputs)
                .proofBytes(proofBytes)
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .build();
    }
}
