package com.bloxbean.cardano.zeroj.patterns.statetransition;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A provable state transition: proves that applying a computation to {@code oldState}
 * produces {@code newState}, without revealing the private inputs to the computation.
 *
 * <p>This is the most fundamental ZK pattern. Example use cases:</p>
 * <ul>
 *   <li>Balance transfers: prove new_balance = old_balance - amount (without revealing balances)</li>
 *   <li>State machine transitions: prove the new state is a valid successor of the old state</li>
 *   <li>Batch computation: prove N operations were applied correctly</li>
 * </ul>
 *
 * <p>The public inputs to the circuit are: [hash(oldState), hash(newState), ...additionalPublicInputs].
 * The private inputs (witness) are the actual state data and computation parameters.</p>
 *
 * @param oldStateHash SHA-256 hash of the previous state (32 bytes)
 * @param newStateHash SHA-256 hash of the new state (32 bytes)
 * @param additionalPublicInputs any extra public values the circuit exposes
 * @param proofBytes the raw proof bytes (snarkjs JSON format)
 * @param proofSystem the proof system used
 * @param curve the elliptic curve used
 * @param circuitId identifier of the circuit that produced this proof
 */
public record StateTransition(
        byte[] oldStateHash,
        byte[] newStateHash,
        List<BigInteger> additionalPublicInputs,
        byte[] proofBytes,
        ProofSystemId proofSystem,
        CurveId curve,
        String circuitId
) {

    public StateTransition {
        Objects.requireNonNull(oldStateHash, "oldStateHash required");
        Objects.requireNonNull(newStateHash, "newStateHash required");
        Objects.requireNonNull(proofBytes, "proofBytes required");
        Objects.requireNonNull(proofSystem, "proofSystem required");
        Objects.requireNonNull(curve, "curve required");
        Objects.requireNonNull(circuitId, "circuitId required");
        if (oldStateHash.length != 32) throw new IllegalArgumentException("oldStateHash must be 32 bytes");
        if (newStateHash.length != 32) throw new IllegalArgumentException("newStateHash must be 32 bytes");
        if (proofBytes.length == 0) throw new IllegalArgumentException("proofBytes must not be empty");
        oldStateHash = oldStateHash.clone();
        newStateHash = newStateHash.clone();
        additionalPublicInputs = additionalPublicInputs != null ? List.copyOf(additionalPublicInputs) : List.of();
        proofBytes = proofBytes.clone();
    }

    @Override public byte[] oldStateHash() { return oldStateHash.clone(); }
    @Override public byte[] newStateHash() { return newStateHash.clone(); }
    @Override public byte[] proofBytes() { return proofBytes.clone(); }

    /**
     * All public inputs in the order expected by the circuit:
     * [newStateHash_as_field, oldStateHash_as_field, ...additional]
     *
     * <p>Note: the ordering depends on the circuit. This is a convention —
     * circuits should document their public input layout.</p>
     */
    public List<BigInteger> allPublicInputs() {
        var all = new java.util.ArrayList<BigInteger>();
        // Convention: circuit outputs first, then public inputs
        // This matches snarkjs ordering (outputs, then inputs)
        all.addAll(additionalPublicInputs);
        return List.copyOf(all);
    }

    /**
     * Compute a deterministic hash of this transition for anchoring.
     */
    public byte[] transitionHash() {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            digest.update(oldStateHash);
            digest.update(newStateHash);
            digest.update(proofSystem.value().getBytes());
            digest.update(curve.value().getBytes());
            digest.update(circuitId.getBytes());
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof StateTransition s
                && Arrays.equals(oldStateHash, s.oldStateHash)
                && Arrays.equals(newStateHash, s.newStateHash)
                && additionalPublicInputs.equals(s.additionalPublicInputs)
                && Arrays.equals(proofBytes, s.proofBytes)
                && proofSystem == s.proofSystem && curve == s.curve
                && circuitId.equals(s.circuitId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(oldStateHash), Arrays.hashCode(newStateHash),
                additionalPublicInputs, proofSystem, curve, circuitId);
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private byte[] oldStateHash;
        private byte[] newStateHash;
        private List<BigInteger> additionalPublicInputs;
        private byte[] proofBytes;
        private ProofSystemId proofSystem = ProofSystemId.GROTH16;
        private CurveId curve = CurveId.BLS12_381;
        private String circuitId;

        public Builder oldStateHash(byte[] v) { this.oldStateHash = v; return this; }
        public Builder newStateHash(byte[] v) { this.newStateHash = v; return this; }
        public Builder additionalPublicInputs(List<BigInteger> v) { this.additionalPublicInputs = v; return this; }
        public Builder proofBytes(byte[] v) { this.proofBytes = v; return this; }
        public Builder proofSystem(ProofSystemId v) { this.proofSystem = v; return this; }
        public Builder curve(CurveId v) { this.curve = v; return this; }
        public Builder circuitId(String v) { this.circuitId = v; return this; }

        public StateTransition build() {
            return new StateTransition(oldStateHash, newStateHash, additionalPublicInputs,
                    proofBytes, proofSystem, curve, circuitId);
        }
    }
}
