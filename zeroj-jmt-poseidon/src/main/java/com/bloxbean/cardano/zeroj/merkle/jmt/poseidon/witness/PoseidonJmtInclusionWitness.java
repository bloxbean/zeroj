package com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.witness;

import com.bloxbean.cardano.vds.jmt.JmtProof;
import com.bloxbean.cardano.vds.jmt.JmtProofVerifier;
import com.bloxbean.cardano.zeroj.circuit.annotation.ZkInputMap;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtCommitmentScheme;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtHashFunction;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.ccl.PoseidonJmtReference;
import com.bloxbean.cardano.zeroj.merkle.jmt.poseidon.profile.PoseidonJmtHash;

import java.math.BigInteger;
import java.util.Objects;

/** Strictly verified JMT inclusion witness. */
public record PoseidonJmtInclusionWitness(
        PoseidonJmtPathWitness path,
        BigInteger valueHash) {

    public PoseidonJmtInclusionWitness {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(valueHash, "valueHash");
    }

    public static PoseidonJmtInclusionWitness create(
            byte[] root, byte[] key, byte[] value, JmtProof proof, int maxLevels) {
        Objects.requireNonNull(proof, "proof");
        if (proof.type() != JmtProof.ProofType.INCLUSION) {
            throw new IllegalArgumentException("expected a JMT inclusion proof");
        }
        if (!PoseidonJmtReference.including(root, key, value, proof)
                || !JmtProofVerifier.verify(root, key, value, proof,
                new PoseidonJmtHashFunction(), new PoseidonJmtCommitmentScheme())) {
            throw new IllegalArgumentException("invalid Poseidon JMT v1 inclusion proof");
        }
        return new PoseidonJmtInclusionWitness(
                PoseidonJmtPathWitness.normalize(key, proof, maxLevels),
                PoseidonJmtHash.decode(PoseidonJmtHash.digest(value)));
    }

    public ZkInputMap putInto(ZkInputMap inputs) {
        path.putInto(inputs);
        return inputs.put("jmt_value_hash", valueHash);
    }
}
