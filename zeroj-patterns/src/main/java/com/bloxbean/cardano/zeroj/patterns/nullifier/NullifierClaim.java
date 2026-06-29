package com.bloxbean.cardano.zeroj.patterns.nullifier;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A nullifier-guarded claim: proves a right to claim something (e.g., tokens, votes)
 * exactly once, without revealing which specific right is being exercised.
 *
 * <p>Example use cases:</p>
 * <ul>
 *   <li>Anonymous voting: prove you're eligible without revealing who you are</li>
 *   <li>Token claims: prove you have an unclaimed airdrop allocation</li>
 *   <li>One-time actions: prove you haven't performed this action before</li>
 * </ul>
 *
 * <p>The nullifier is a deterministic value derived from the secret input.
 * Publishing it on-chain prevents double-claiming without revealing the claimer's identity.</p>
 *
 * @param nullifier           deterministic hash derived from secret input (published on-chain)
 * @param commitment          commitment to the claim (e.g., Merkle root of eligible set)
 * @param claimValue          the claimed output value (public)
 * @param additionalPublicInputs any extra public values
 * @param proofBytes          the raw proof bytes
 * @param proofSystem         the proof system used
 * @param curve               the elliptic curve used
 * @param circuitId           identifier of the circuit
 */
public record NullifierClaim(
        byte[] nullifier,
        byte[] commitment,
        BigInteger claimValue,
        List<BigInteger> additionalPublicInputs,
        byte[] proofBytes,
        ProofSystemId proofSystem,
        CurveId curve,
        String circuitId
) {

    public NullifierClaim {
        Objects.requireNonNull(nullifier, "nullifier required");
        Objects.requireNonNull(commitment, "commitment required");
        Objects.requireNonNull(proofBytes, "proofBytes required");
        Objects.requireNonNull(proofSystem, "proofSystem required");
        Objects.requireNonNull(curve, "curve required");
        Objects.requireNonNull(circuitId, "circuitId required");
        if (nullifier.length == 0) throw new IllegalArgumentException("nullifier must not be empty");
        if (commitment.length == 0) throw new IllegalArgumentException("commitment must not be empty");
        if (proofBytes.length == 0) throw new IllegalArgumentException("proofBytes must not be empty");
        nullifier = nullifier.clone();
        commitment = commitment.clone();
        additionalPublicInputs = additionalPublicInputs != null ? List.copyOf(additionalPublicInputs) : List.of();
        proofBytes = proofBytes.clone();
    }

    @Override public byte[] nullifier() { return nullifier.clone(); }
    @Override public byte[] commitment() { return commitment.clone(); }
    @Override public byte[] proofBytes() { return proofBytes.clone(); }

    /**
     * All public inputs for the circuit.
     * Convention: [nullifier_as_field, commitment_as_field, claimValue, ...additional]
     */
    public List<BigInteger> allPublicInputs() {
        var all = new java.util.ArrayList<BigInteger>();
        if (claimValue != null) all.add(claimValue);
        all.addAll(additionalPublicInputs);
        return List.copyOf(all);
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private byte[] nullifier;
        private byte[] commitment;
        private BigInteger claimValue;
        private List<BigInteger> additionalPublicInputs;
        private byte[] proofBytes;
        private ProofSystemId proofSystem = ProofSystemId.GROTH16;
        private CurveId curve = CurveId.BLS12_381;
        private String circuitId;

        public Builder nullifier(byte[] v) { this.nullifier = v; return this; }
        public Builder commitment(byte[] v) { this.commitment = v; return this; }
        public Builder claimValue(BigInteger v) { this.claimValue = v; return this; }
        public Builder additionalPublicInputs(List<BigInteger> v) { this.additionalPublicInputs = v; return this; }
        public Builder proofBytes(byte[] v) { this.proofBytes = v; return this; }
        public Builder proofSystem(ProofSystemId v) { this.proofSystem = v; return this; }
        public Builder curve(CurveId v) { this.curve = v; return this; }
        public Builder circuitId(String v) { this.circuitId = v; return this; }

        public NullifierClaim build() {
            return new NullifierClaim(nullifier, commitment, claimValue, additionalPublicInputs,
                    proofBytes, proofSystem, curve, circuitId);
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof NullifierClaim c
                && Arrays.equals(nullifier, c.nullifier)
                && Arrays.equals(commitment, c.commitment)
                && Objects.equals(claimValue, c.claimValue)
                && Arrays.equals(proofBytes, c.proofBytes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(nullifier), Arrays.hashCode(commitment), claimValue);
    }
}
