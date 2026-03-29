package com.bloxbean.cardano.zeroj.examples.dsl.auction;

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
 * Connects the {@link SealedBidCircuit} to snarkjs for proof generation.
 *
 * <p>Handles the full lifecycle:</p>
 * <ol>
 *   <li>Compile circuit to R1CS (pure Java)</li>
 *   <li>Compute bid commitment via standalone MiMC hash</li>
 *   <li>Calculate witness and export to .wtns (pure Java)</li>
 *   <li>Call snarkjs for trusted setup + proof generation</li>
 * </ol>
 */
public class SealedBidProofHelper {

    private final CurveId curve;

    public SealedBidProofHelper(CurveId curve) {
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
     * Compute the bid commitment: MiMC(bidAmount, salt).
     */
    public BigInteger computeCommitment(BigInteger bidAmount, BigInteger salt) {
        return MiMCHash.hash(bidAmount, salt, FieldConfig.forCurve(curve).prime());
    }

    /**
     * Generate .wtns binary for the given bid parameters.
     *
     * <p>Computes bidCommitment and isAboveReserve internally.</p>
     */
    public byte[] generateWitness(BigInteger bidAmount, BigInteger salt, BigInteger reservePrice) {
        var config = FieldConfig.forCurve(curve);
        var bidCommitment = computeCommitment(bidAmount, salt);
        var isAboveReserve = bidAmount.compareTo(reservePrice) >= 0
                ? BigInteger.ONE : BigInteger.ZERO;

        var circuit = SealedBidCircuit.build();
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "bidAmount", List.of(bidAmount),
                "salt", List.of(salt),
                "bidCommitment", List.of(bidCommitment),
                "reservePrice", List.of(reservePrice),
                "isAboveReserve", List.of(isAboveReserve)
        ), curve);

        return WitnessExporter.toWtns(witness, config.prime(), config.n32());
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
        var isAboveReserve = bidAmount.compareTo(reservePrice) >= 0
                ? BigInteger.ONE : BigInteger.ZERO;

        return GnarkProverHelper.groth16Prove(
                SealedBidCircuit.build(),
                Map.of(
                        "bidAmount", List.of(bidAmount),
                        "salt", List.of(salt),
                        "bidCommitment", List.of(bidCommitment),
                        "reservePrice", List.of(reservePrice),
                        "isAboveReserve", List.of(isAboveReserve)
                ),
                curve, prover);
    }
}
