package com.bloxbean.cardano.zeroj.examples.dsl.common;

import com.bloxbean.cardano.zeroj.api.CurveId;
import com.bloxbean.cardano.zeroj.circuit.CircuitBuilder;
import com.bloxbean.cardano.zeroj.circuit.FieldConfig;
import com.bloxbean.cardano.zeroj.circuit.r1cs.R1CSSerializer;
import com.bloxbean.cardano.zeroj.prover.wasm.WitnessExporter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests that the SnarkjsProver correctly shells out to snarkjs
 * and produces valid proofs from Java-generated .r1cs + .wtns files.
 */
@Tag("e2e")
class SnarkjsProverTest {

    private static SnarkjsProver prover;

    @BeforeAll
    static void checkSnarkjs() {
        prover = new SnarkjsProver();
        assumeTrue(prover.isAvailable(), "snarkjs not found — skipping SnarkjsProverTest");
    }

    /**
     * Simplest possible circuit: x * y = z (1 constraint).
     * Proves 3 * 11 = 33 with BN254 Groth16.
     */
    @Test
    void groth16_bn254_simpleMultiplier(@TempDir Path workDir) throws Exception {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(
                        api.mul(api.var("x"), api.var("y")),
                        api.var("z")));

        var config = FieldConfig.BN254;
        byte[] r1cs = R1CSSerializer.serialize(circuit.compileR1CS(CurveId.BN254));
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        byte[] wtns = WitnessExporter.toWtns(witness, config.prime(), config.n32());

        // Phase 1: Powers of Tau
        Path ptau = prover.powersOfTau("bn128", 10, workDir);
        assertTrue(ptau.toFile().exists(), "ptau file should exist");

        // Phase 2: Groth16 setup
        var setup = prover.groth16Setup(r1cs, ptau, workDir);
        assertNotNull(setup.vkJson());
        assertTrue(setup.vkJson().contains("\"protocol\""));
        assertTrue(setup.vkJson().contains("\"groth16\""));

        // Prove
        var proof = prover.groth16Prove(setup.zkeyFile(), wtns, workDir, setup.vkJson());
        assertNotNull(proof.proofJson());
        assertNotNull(proof.publicJson());
        assertTrue(proof.proofJson().contains("\"pi_a\""));
        assertTrue(proof.publicJson().contains("33")); // public input z=33

        // Verify via snarkjs CLI
        assertTrue(prover.groth16Verify(workDir), "Groth16 proof should verify");
    }

    /**
     * Same circuit, BLS12-381 Groth16 — the curve used for Cardano on-chain verification.
     */
    @Test
    void groth16_bls12381_simpleMultiplier(@TempDir Path workDir) throws Exception {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(
                        api.mul(api.var("x"), api.var("y")),
                        api.var("z")));

        var config = FieldConfig.BLS12_381;
        byte[] r1cs = R1CSSerializer.serialize(circuit.compileR1CS(CurveId.BLS12_381));
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BLS12_381);
        byte[] wtns = WitnessExporter.toWtns(witness, config.prime(), config.n32());

        Path ptau = prover.powersOfTau("bls12-381", 10, workDir);
        var setup = prover.groth16Setup(r1cs, ptau, workDir);
        var proof = prover.groth16Prove(setup.zkeyFile(), wtns, workDir, setup.vkJson());

        assertTrue(proof.proofJson().contains("\"pi_a\""));
        assertTrue(proof.vkJson().contains("\"bls12381\""));
        assertTrue(prover.groth16Verify(workDir));
    }

    /**
     * PlonK with BN254 — no Phase 2 ceremony needed.
     */
    @Test
    void plonk_bn254_simpleMultiplier(@TempDir Path workDir) throws Exception {
        var circuit = CircuitBuilder.create("multiplier")
                .publicVar("z").secretVar("x").secretVar("y")
                .define(api -> api.assertEqual(
                        api.mul(api.var("x"), api.var("y")),
                        api.var("z")));

        var config = FieldConfig.BN254;
        byte[] r1cs = R1CSSerializer.serialize(circuit.compileR1CS(CurveId.BN254));
        BigInteger[] witness = circuit.calculateWitness(Map.of(
                "z", List.of(BigInteger.valueOf(33)),
                "x", List.of(BigInteger.valueOf(3)),
                "y", List.of(BigInteger.valueOf(11))), CurveId.BN254);
        byte[] wtns = WitnessExporter.toWtns(witness, config.prime(), config.n32());

        Path ptau = prover.powersOfTau("bn128", 10, workDir);
        var setup = prover.plonkSetup(r1cs, ptau, workDir);
        var proof = prover.plonkProve(setup.zkeyFile(), wtns, workDir, setup.vkJson());

        assertNotNull(proof.proofJson());
        assertTrue(proof.proofJson().contains("\"protocol\":\"plonk\"")
                || proof.proofJson().contains("\"protocol\": \"plonk\""));
        assertTrue(prover.plonkVerify(workDir));
    }
}
