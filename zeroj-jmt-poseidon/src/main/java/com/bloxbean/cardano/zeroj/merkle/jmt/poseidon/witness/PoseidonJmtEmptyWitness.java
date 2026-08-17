package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProofVerifier;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtCommitmentScheme;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtHashFunction;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtReference;

import java.util.Objects;

/** Strictly verified authenticated-empty JMT non-inclusion witness. */
public record PoseidonJmtEmptyWitness(PoseidonJmtPathWitness path) {
    public PoseidonJmtEmptyWitness {
        Objects.requireNonNull(path, "path");
    }

    public static PoseidonJmtEmptyWitness create(
            byte[] root, byte[] key, JmtProof proof, int maxLevels) {
        Objects.requireNonNull(proof, "proof");
        if (proof.type() != JmtProof.ProofType.NON_INCLUSION_EMPTY) {
            throw new IllegalArgumentException("expected an authenticated-empty JMT proof");
        }
        if (!PoseidonJmtReference.excluding(root, key, proof)
                || !JmtProofVerifier.verify(root, key, null, proof,
                new PoseidonJmtHashFunction(), new PoseidonJmtCommitmentScheme())) {
            throw new IllegalArgumentException("invalid Poseidon JMT v1 empty proof");
        }
        return new PoseidonJmtEmptyWitness(
                PoseidonJmtPathWitness.normalize(key, proof, maxLevels));
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        return path.putInto(inputs);
    }
}
