package com.bloxbean.cardano.zeroj.examples.dsl.voting;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSSerializer;
import com.bloxbean.cardano.zeroj.examples.dsl.common.GnarkProverHelper;
import com.bloxbean.cardano.zeroj.examples.dsl.common.MiMCHash;
import com.bloxbean.cardano.zeroj.examples.dsl.common.SnarkjsProver;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.prover.wasm.WitnessExporter;

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
     * Compute the vote commitment: MiMC(vote, nullifier).
     */
    public BigInteger computeCommitment(BigInteger vote, BigInteger nullifier) {
        return MiMCHash.hash(vote, nullifier, FieldConfig.forCurve(curve).prime());
    }

    /**
     * Generate .wtns binary for the given vote parameters.
     *
     * @param vote      0 or 1
     * @param nullifier unique per voter (prevents double-voting)
     */
    public byte[] generateWitness(BigInteger vote, BigInteger nullifier) {
        var config = FieldConfig.forCurve(curve);
        var commitment = computeCommitment(vote, nullifier);

        var circuit = AnonymousVotingCircuit.build();
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "vote", List.of(vote),
                "nullifier", List.of(nullifier),
                "commitment", List.of(commitment)
        ), curve);

        return WitnessExporter.toWtns(witness, config.prime(), config.n32());
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

    /**
     * Groth16 proof via gnark FFM — no external tools needed.
     */
    public GnarkProver.FullProveResponse generateGroth16ProofNative(
            BigInteger vote, BigInteger nullifier, GnarkProver prover) {

        var commitment = computeCommitment(vote, nullifier);

        return GnarkProverHelper.groth16Prove(
                AnonymousVotingCircuit.build(),
                Map.of(
                        "vote", List.of(vote),
                        "nullifier", List.of(nullifier),
                        "commitment", List.of(commitment)
                ),
                curve, prover);
    }
}
