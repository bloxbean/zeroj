package com.bloxbean.cardano.zeroj.examples.dsl.auction;

import com.bloxbean.cardano.zeroj.api.*;
import com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec;
import com.bloxbean.cardano.zeroj.examples.dsl.common.SnarkjsProver;
import com.bloxbean.cardano.zeroj.verifier.groth16.bls12381.Groth16BLS12381PureJavaVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * E2E test: Java DSL circuit → R1CS + witness → snarkjs Groth16 prove → off-chain Java verify.
 *
 * <p>This demonstrates the complete flow:</p>
 * <ol>
 *   <li>Define the SealedBidCircuit in Java (CircuitSpec)</li>
 *   <li>Compile to R1CS binary (pure Java)</li>
 *   <li>Calculate witness and export to .wtns (pure Java)</li>
 *   <li>Run snarkjs Groth16 trusted setup + proof generation (CLI)</li>
 *   <li>Verify the proof off-chain using pure Java BLS12-381 verifier</li>
 * </ol>
 *
 * <p>Requires snarkjs to be installed: {@code npm install -g snarkjs}</p>
 */
@Tag("e2e")
class SealedBidE2ETest {

    private static SnarkjsProver snarkjs;

    @BeforeAll
    static void checkPrerequisites() {
        snarkjs = new SnarkjsProver();
        assumeTrue(snarkjs.isAvailable(), "snarkjs not found — skipping E2E tests");
    }

    /**
     * Groth16/BLS12-381: sealed bid with bid above reserve price.
     */
    @Test
    void groth16_bls12381_bidAboveReserve(@TempDir Path workDir) throws Exception {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);

        // Bid parameters
        var bidAmount = BigInteger.valueOf(1000);
        var salt = BigInteger.valueOf(42);
        var reservePrice = BigInteger.valueOf(500);

        // 1. Powers of Tau (Phase 1)
        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);

        // 2. Full Groth16 proof generation (R1CS + witness + setup + prove)
        var proof = helper.generateGroth16Proof(bidAmount, salt, reservePrice, ptau, workDir, snarkjs);

        // 3. Verify via snarkjs CLI
        assertTrue(snarkjs.groth16Verify(workDir), "snarkjs CLI should verify the proof");

        // 4. Verify off-chain using pure Java BLS12-381 verifier
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                proof.proofJson(), proof.vkJson(), proof.publicJson(),
                new CircuitId("sealed-bid"));

        byte[] vkBytes = proof.vkJson().getBytes(StandardCharsets.UTF_8);
        var material = VerificationMaterial.of(
                vkBytes, ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("sealed-bid"));

        var verifier = new Groth16BLS12381PureJavaVerifier();
        var result = verifier.verify(envelope, material);

        assertTrue(result.proofValid(), "Pure Java verifier should accept the proof: " + result);

        // 5. Verify public inputs contain expected values
        var publicInputs = SnarkjsJsonCodec.parsePublicInputs(proof.publicJson());
        // Public vars: [bidCommitment, reservePrice]
        assertEquals(2, publicInputs.size(), "Should have 2 public inputs");
        assertEquals(helper.computeCommitment(bidAmount, salt), publicInputs.get(0),
                "Public commitment should match BLS12-381 Poseidon");
        assertEquals(reservePrice, publicInputs.get(1),
                "Public reserve price should match the witness");

    }

    /**
     * Groth16/BLS12-381: sealed bid BELOW reserve price fails witness
     * calculation because the reserve condition is constrained in-circuit.
     */
    @Test
    void groth16_bls12381_bidBelowReserve_failsWitness(@TempDir Path workDir) throws Exception {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);

        var bidAmount = BigInteger.valueOf(200);
        var salt = BigInteger.valueOf(99);
        var reservePrice = BigInteger.valueOf(500);

        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
        assertThrows(ArithmeticException.class,
                () -> helper.generateGroth16Proof(bidAmount, salt, reservePrice, ptau, workDir, snarkjs));
    }

    /**
     * PlonK/BLS12-381: same circuit, PlonK proof system.
     * Verified via snarkjs CLI (Java PlonK verification of snarkjs proofs needs a codec).
     */
    @Test
    void plonk_bls12381_bidAboveReserve(@TempDir Path workDir) throws Exception {
        var helper = new SealedBidProofHelper(CurveId.BLS12_381);

        var bidAmount = BigInteger.valueOf(1000);
        var salt = BigInteger.valueOf(42);
        var reservePrice = BigInteger.valueOf(500);

        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
        var proof = helper.generatePlonkProof(bidAmount, salt, reservePrice, ptau, workDir, snarkjs);

        assertNotNull(proof.proofJson());
        assertTrue(proof.proofJson().contains("\"plonk\""), "Should be PlonK proof");

        // Verify via snarkjs CLI
        assertTrue(snarkjs.plonkVerify(workDir), "snarkjs CLI should verify PlonK proof");
    }
}
