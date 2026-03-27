package com.bloxbean.cardano.zeroj.patterns.statetransition;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;

/**
 * Input data for a state transition — bridges domain concepts to the proof layer.
 * <p>
 * Captures old/new state data before proof generation. Once a proof is obtained
 * (from snarkjs, sidecar, or any prover), call {@link #withProof} to produce a
 * {@link StateTransition} ready for verification.
 * <p>
 * Example:
 * <pre>{@code
 * // 1. Prepare input from domain data
 * var input = StateTransitionInput.fromRawStates(
 *     oldAccountBytes, newAccountBytes,
 *     List.of(BigInteger.valueOf(transferAmount)));
 *
 * // 2. Generate proof externally (snarkjs, sidecar, etc.)
 * byte[] proofBytes = prover.prove(input.oldStateHash(), input.newStateHash(), witness);
 *
 * // 3. Create typed transition for verification
 * StateTransition transition = input.withProof(proofBytes, "balance-transfer");
 * }</pre>
 *
 * @param oldStateHash         SHA-256 hash of the previous state (32 bytes)
 * @param newStateHash         SHA-256 hash of the new state (32 bytes)
 * @param additionalPublicInputs extra public values for the circuit
 */
public record StateTransitionInput(
        byte[] oldStateHash,
        byte[] newStateHash,
        List<BigInteger> additionalPublicInputs
) {

    public StateTransitionInput {
        Objects.requireNonNull(oldStateHash, "oldStateHash required");
        Objects.requireNonNull(newStateHash, "newStateHash required");
        if (oldStateHash.length != 32) throw new IllegalArgumentException("oldStateHash must be 32 bytes");
        if (newStateHash.length != 32) throw new IllegalArgumentException("newStateHash must be 32 bytes");
        oldStateHash = oldStateHash.clone();
        newStateHash = newStateHash.clone();
        additionalPublicInputs = additionalPublicInputs != null ? List.copyOf(additionalPublicInputs) : List.of();
    }

    @Override public byte[] oldStateHash() { return oldStateHash.clone(); }
    @Override public byte[] newStateHash() { return newStateHash.clone(); }

    /**
     * Create input by hashing raw state data (SHA-256).
     */
    public static StateTransitionInput fromRawStates(byte[] oldState, byte[] newState,
                                                      List<BigInteger> additionalPublicInputs) {
        return new StateTransitionInput(sha256(oldState), sha256(newState), additionalPublicInputs);
    }

    /**
     * Create input from pre-computed state hashes.
     */
    public static StateTransitionInput of(byte[] oldStateHash, byte[] newStateHash,
                                           List<BigInteger> additionalPublicInputs) {
        return new StateTransitionInput(oldStateHash, newStateHash, additionalPublicInputs);
    }

    /**
     * Attach a proof to produce a verified {@link StateTransition}.
     *
     * @param proofBytes the proof bytes from the prover
     * @param circuitId  the circuit that generated the proof
     * @return a {@link StateTransition} ready for verification
     */
    public StateTransition withProof(byte[] proofBytes, String circuitId) {
        return withProof(proofBytes, circuitId, ProofSystemId.GROTH16, CurveId.BN254);
    }

    /**
     * Attach a proof with explicit proof system and curve.
     */
    public StateTransition withProof(byte[] proofBytes, String circuitId,
                                      ProofSystemId proofSystem, CurveId curve) {
        return StateTransition.builder()
                .oldStateHash(oldStateHash)
                .newStateHash(newStateHash)
                .additionalPublicInputs(additionalPublicInputs)
                .proofBytes(proofBytes)
                .proofSystem(proofSystem)
                .curve(curve)
                .circuitId(circuitId)
                .build();
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (NoSuchAlgorithmException e) { throw new RuntimeException(e); }
    }
}
