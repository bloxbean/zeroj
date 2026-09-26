package org.zeroj.examples.dsl.balance;

import org.zeroj.api.CurveId;
import org.zeroj.circuit.FieldConfig;
import org.zeroj.circuit.r1cs.R1CSSerializer;
import org.zeroj.examples.dsl.common.SnarkjsProver;
import org.zeroj.examples.dsl.common.WitnessExporter;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Connects the {@link BalanceThresholdCircuit} to snarkjs for proof generation.
 */
public class BalanceThresholdProofHelper {

    private final CurveId curve;

    public BalanceThresholdProofHelper(CurveId curve) {
        this.curve = curve;
    }

    /**
     * Generate .r1cs binary from the balance threshold circuit.
     */
    public byte[] generateR1CS() {
        var circuit = BalanceThresholdCircuit.build();
        return R1CSSerializer.serialize(circuit.compileR1CS(curve));
    }

    /**
     * Generate .wtns binary for the given parameters.
     *
     * @param balance   the private balance
     * @param threshold the public threshold
     */
    public byte[] generateWitness(BigInteger balance, BigInteger threshold) {
        var config = FieldConfig.forCurve(curve);
        var isAboveThreshold = balance.compareTo(threshold) >= 0
                ? BigInteger.ONE : BigInteger.ZERO;

        var circuit = BalanceThresholdCircuit.build();
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "balance", List.of(balance),
                "threshold", List.of(threshold),
                "isAboveThreshold", List.of(isAboveThreshold)
        ), curve);

        return WitnessExporter.toWtns(witness, config.prime(), config.n32());
    }

    /**
     * Full Groth16 proof generation.
     */
    public SnarkjsProver.ProofResult generateGroth16Proof(
            BigInteger balance, BigInteger threshold,
            Path ptauFile, Path workDir, SnarkjsProver prover) throws Exception {

        byte[] r1cs = generateR1CS();
        byte[] wtns = generateWitness(balance, threshold);

        var setup = prover.groth16Setup(r1cs, ptauFile, workDir);
        return prover.groth16Prove(setup.zkeyFile(), wtns, workDir, setup.vkJson());
    }
}
