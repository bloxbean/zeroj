package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProofVerifier;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtCommitmentScheme;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtHashFunction;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtReference;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/** Strictly verified conflicting-leaf JMT non-inclusion witness. */
public record PoseidonJmtDifferentLeafWitness(
        PoseidonJmtPathWitness path,
        List<BigInteger> conflictingKeyNibbles,
        BigInteger conflictingValueHash) {

    public PoseidonJmtDifferentLeafWitness {
        Objects.requireNonNull(path, "path");
        conflictingKeyNibbles = List.copyOf(
                Objects.requireNonNull(conflictingKeyNibbles, "conflictingKeyNibbles"));
        if (conflictingKeyNibbles.size() != 64) {
            throw new IllegalArgumentException("conflicting key must contain 64 nibbles");
        }
        Objects.requireNonNull(conflictingValueHash, "conflictingValueHash");
    }

    public static PoseidonJmtDifferentLeafWitness create(
            byte[] root, byte[] key, JmtProof proof, int maxLevels) {
        Objects.requireNonNull(proof, "proof");
        if (proof.type() != JmtProof.ProofType.NON_INCLUSION_DIFFERENT_LEAF) {
            throw new IllegalArgumentException("expected a different-leaf JMT proof");
        }
        if (!PoseidonJmtReference.excluding(root, key, proof)
                || !JmtProofVerifier.verify(root, key, null, proof,
                new PoseidonJmtHashFunction(), new PoseidonJmtCommitmentScheme())) {
            throw new IllegalArgumentException("invalid Poseidon JMT v1 different-leaf proof");
        }
        int[] nibbles = PoseidonJmtHash.nibbles(proof.conflictingKeyHash());
        return new PoseidonJmtDifferentLeafWitness(
                PoseidonJmtPathWitness.normalize(key, proof, maxLevels),
                Arrays.stream(nibbles).mapToObj(BigInteger::valueOf).toList(),
                PoseidonJmtHash.decode(proof.conflictingValueHash()));
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        path.putInto(inputs);
        return inputs.putArray("jmt_conflicting_key_nibble", conflictingKeyNibbles)
                .put("jmt_conflicting_value_hash", conflictingValueHash);
    }
}
