package org.zeroj.examples.dsl.voting;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.r1cs.R1CSSerializer;
import org.zeroj.circuit.lib.poseidon.PoseidonHash;
import org.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import org.zeroj.examples.dsl.common.SnarkjsProver;
import org.zeroj.examples.dsl.common.WitnessExporter;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Connects the {@link AnonymousVotingCircuit} to snarkjs for proof generation.
 */
public class AnonymousVotingProofHelper {

    private final CurveId curve;

    public AnonymousVotingProofHelper(CurveId curve) {
        if (curve != CurveId.BLS12_381) {
            throw new IllegalArgumentException("AnonymousVotingCircuit uses explicit BLS12-381 Poseidon params");
        }
        this.curve = curve;
    }

    /**
     * Generate .r1cs binary from the voting circuit.
     */
    public byte[] generateR1CS() {
        var circuit = AnonymousVotingCircuit.build();
        return R1CSSerializer.serialize(circuit.compileR1CS(curve));
    }

    /**
     * Compute the vote commitment: PoseidonBLS12_381(vote, nullifier).
     */
    public BigInteger computeCommitment(BigInteger vote, BigInteger nullifier) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, vote, nullifier);
    }

    /**
     * Generate .wtns binary for the given vote parameters.
     *
     * @param vote      0 or 1
     * @param nullifier unique per voter (prevents double-voting)
     */
    public byte[] generateWitness(BigInteger vote, BigInteger nullifier) {
        var commitment = computeCommitment(vote, nullifier);

        var circuit = AnonymousVotingCircuit.build();
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "vote", List.of(vote),
                "nullifier", List.of(nullifier),
                "commitment", List.of(commitment)
        ), curve);

        return WitnessExporter.toWtns(witness,
                PoseidonParamsBLS12_381T3.INSTANCE.field().prime(),
                PoseidonParamsBLS12_381T3.INSTANCE.field().n32());
    }

    /**
     * Full Groth16 proof generation.
     */
    public SnarkjsProver.ProofResult generateGroth16Proof(
            BigInteger vote, BigInteger nullifier,
            Path ptauFile, Path workDir, SnarkjsProver prover) throws Exception {

        byte[] r1cs = generateR1CS();
        byte[] wtns = generateWitness(vote, nullifier);

        var setup = prover.groth16Setup(r1cs, ptauFile, workDir);
        return prover.groth16Prove(setup.zkeyFile(), wtns, workDir, setup.vkJson());
    }
}
