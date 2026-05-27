package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSSerializer;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonHash;
import com.bloxbean.cardano.zeroj.circuit.lib.poseidon.PoseidonParamsBLS12_381T3;
import com.bloxbean.cardano.zeroj.examples.dsl.common.GnarkProverHelper;
import com.bloxbean.cardano.zeroj.examples.dsl.common.SnarkjsProver;
import com.bloxbean.cardano.zeroj.prover.gnark.GnarkProver;
import com.bloxbean.cardano.zeroj.prover.wasm.WitnessExporter;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Connects the {@link SealedBidCircuit} to snarkjs for proof generation.
 *
 * <p>Handles the full lifecycle:</p>
 * <ol>
 *   <li>Compile circuit to R1CS (pure Java)</li>
 *   <li>Compute bid commitment via standalone BLS12-381 Poseidon hash</li>
 *   <li>Calculate witness and export to .wtns (pure Java)</li>
 *   <li>Call snarkjs for trusted setup + proof generation</li>
 * </ol>
 */
public class SealedBidProofHelper {

    private final CurveId curve;

    public SealedBidProofHelper(CurveId curve) {
        if (curve != CurveId.BLS12_381) {
            throw new IllegalArgumentException("SealedBidCircuit uses explicit BLS12-381 Poseidon params");
        }
        this.curve = curve;
    }

    /**
     * Generate .r1cs binary from the sealed-bid circuit.
     */
    public byte[] generateR1CS() {
        var circuit = SealedBidCircuit.build();
        return R1CSSerializer.serialize(circuit.compileR1CS(curve));
    }

    /**
     * Compute the bid commitment: PoseidonBLS12_381(bidAmount, salt).
     */
    public BigInteger computeCommitment(BigInteger bidAmount, BigInteger salt) {
        return PoseidonHash.hash(PoseidonParamsBLS12_381T3.INSTANCE, bidAmount, salt);
    }

    /**
     * Generate .wtns binary for the given bid parameters.
     *
     * <p>Computes bidCommitment internally. Bids below reserve fail witness
     * calculation because the reserve check is constrained inside the circuit.</p>
     */
    public byte[] generateWitness(BigInteger bidAmount, BigInteger salt, BigInteger reservePrice) {
        var bidCommitment = computeCommitment(bidAmount, salt);

        var circuit = SealedBidCircuit.build();
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "bidCommitment", List.of(bidCommitment),
                "reservePrice", List.of(reservePrice)
        ), curve);

        return WitnessExporter.toWtns(witness,
                PoseidonParamsBLS12_381T3.INSTANCE.field().prime(),
                PoseidonParamsBLS12_381T3.INSTANCE.field().n32());
    }

    /**
     * Full Groth16 proof generation: R1CS + witness → snarkjs setup → snarkjs prove.
     *
     * @param bidAmount    the private bid amount
     * @param salt         the private salt for commitment
     * @param reservePrice the public reserve price
     * @param ptauFile     path to finalized Powers of Tau file
     * @param workDir      working directory for snarkjs temp files
     * @param prover       snarkjs CLI wrapper
     * @return proof result with proof JSON, public inputs JSON, and verification key JSON
     */
    public SnarkjsProver.ProofResult generateGroth16Proof(
            BigInteger bidAmount, BigInteger salt, BigInteger reservePrice,
            Path ptauFile, Path workDir, SnarkjsProver prover) throws Exception {

        byte[] r1cs = generateR1CS();
        byte[] wtns = generateWitness(bidAmount, salt, reservePrice);

        var setup = prover.groth16Setup(r1cs, ptauFile, workDir);
        return prover.groth16Prove(setup.zkeyFile(), wtns, workDir, setup.vkJson());
    }

    /**
     * Full PlonK proof generation.
     */
    public SnarkjsProver.ProofResult generatePlonkProof(
            BigInteger bidAmount, BigInteger salt, BigInteger reservePrice,
            Path ptauFile, Path workDir, SnarkjsProver prover) throws Exception {

        byte[] r1cs = generateR1CS();
        byte[] wtns = generateWitness(bidAmount, salt, reservePrice);

        var setup = prover.plonkSetup(r1cs, ptauFile, workDir);
        return prover.plonkProve(setup.zkeyFile(), wtns, workDir, setup.vkJson());
    }

    /**
     * Groth16 proof via gnark FFM — no external tools needed.
     */
    public GnarkProver.FullProveResponse generateGroth16ProofNative(
            BigInteger bidAmount, BigInteger salt, BigInteger reservePrice,
            GnarkProver prover) {

        var bidCommitment = computeCommitment(bidAmount, salt);

        return GnarkProverHelper.groth16Prove(
                SealedBidCircuit.build(),
                Map.of(
                        "bidAmount", List.of(bidAmount),
                        "salt", List.of(salt),
                        "bidCommitment", List.of(bidCommitment),
                        "reservePrice", List.of(reservePrice)
                ),
                curve, prover);
    }
}
