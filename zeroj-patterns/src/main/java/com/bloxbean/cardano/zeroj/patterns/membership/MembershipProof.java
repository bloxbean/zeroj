package com.bloxbean.cardano.zeroj.patterns.membership;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.api.ProofSystemId;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * A membership proof with constraints: proves that an element belongs to a set
 * (represented by a Merkle root) AND satisfies additional constraints,
 * without revealing which element.
 *
 * <p>Example use cases:</p>
 * <ul>
 *   <li>Prove you're in a whitelist without revealing your identity</li>
 *   <li>Prove you hold a token with value >= threshold without revealing exact amount</li>
 *   <li>Prove you're an eligible voter in a specific jurisdiction</li>
 * </ul>
 *
 * <p>Public inputs typically: [merkleRoot, constraintOutputs...]
 * Private inputs (witness): [leaf, merklePathElements, merklePathIndices, ...]</p>
 *
 * @param merkleRoot the root of the Merkle tree (commitment to the set)
 * @param constraintOutputs public outputs from constraint evaluation
 * @param proofBytes the raw proof bytes
 * @param proofSystem the proof system used
 * @param curve the elliptic curve used
 * @param circuitId identifier of the circuit
 */
public record MembershipProof(
        byte[] merkleRoot,
        List<BigInteger> constraintOutputs,
        byte[] proofBytes,
        ProofSystemId proofSystem,
        CurveId curve,
        String circuitId
) {

    public MembershipProof {
        Objects.requireNonNull(merkleRoot, "merkleRoot required");
        Objects.requireNonNull(proofBytes, "proofBytes required");
        Objects.requireNonNull(proofSystem, "proofSystem required");
        Objects.requireNonNull(curve, "curve required");
        Objects.requireNonNull(circuitId, "circuitId required");
        if (merkleRoot.length == 0) throw new IllegalArgumentException("merkleRoot must not be empty");
        if (proofBytes.length == 0) throw new IllegalArgumentException("proofBytes must not be empty");
        merkleRoot = merkleRoot.clone();
        constraintOutputs = constraintOutputs != null ? List.copyOf(constraintOutputs) : List.of();
        proofBytes = proofBytes.clone();
    }

    @Override public byte[] merkleRoot() { return merkleRoot.clone(); }
    @Override public byte[] proofBytes() { return proofBytes.clone(); }

    /**
     * All public inputs for the circuit.
     * Convention: [constraintOutputs...]
     * The merkle root may or may not be a public input depending on the circuit design.
     */
    public List<BigInteger> allPublicInputs() {
        return constraintOutputs;
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private byte[] merkleRoot;
        private List<BigInteger> constraintOutputs;
        private byte[] proofBytes;
        private ProofSystemId proofSystem = ProofSystemId.GROTH16;
        private CurveId curve = CurveId.BN254;
        private String circuitId;

        public Builder merkleRoot(byte[] v) { this.merkleRoot = v; return this; }
        public Builder constraintOutputs(List<BigInteger> v) { this.constraintOutputs = v; return this; }
        public Builder proofBytes(byte[] v) { this.proofBytes = v; return this; }
        public Builder proofSystem(ProofSystemId v) { this.proofSystem = v; return this; }
        public Builder curve(CurveId v) { this.curve = v; return this; }
        public Builder circuitId(String v) { this.circuitId = v; return this; }

        public MembershipProof build() {
            return new MembershipProof(merkleRoot, constraintOutputs, proofBytes,
                    proofSystem, curve, circuitId);
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof MembershipProof m
                && Arrays.equals(merkleRoot, m.merkleRoot)
                && constraintOutputs.equals(m.constraintOutputs)
                && Arrays.equals(proofBytes, m.proofBytes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(Arrays.hashCode(merkleRoot), constraintOutputs);
    }
}
