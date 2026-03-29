package com.bloxbean.cardano.zeroj.examples.dsl.balance;

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
 * E2E test: BalanceThresholdCircuit → snarkjs Groth16 → off-chain Java verify.
 *
 * <p>Also demonstrates <b>verifier reusability</b>: the same Groth16BLS12381PureJavaVerifier
 * verifies proofs from different circuits (SealedBid, BalanceThreshold) — only the VK changes.</p>
 */
@Tag("e2e")
class BalanceThresholdE2ETest {

    private static SnarkjsProver snarkjs;

    @BeforeAll
    static void checkPrerequisites() {
        snarkjs = new SnarkjsProver();
        assumeTrue(snarkjs.isAvailable(), "snarkjs not found — skipping E2E tests");
    }

    @Test
    void groth16_bls12381_balanceAboveThreshold(@TempDir Path workDir) throws Exception {
        var helper = new BalanceThresholdProofHelper(CurveId.BLS12_381);

        var balance = BigInteger.valueOf(10_000);
        var threshold = BigInteger.valueOf(5_000);

        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
        var proof = helper.generateGroth16Proof(balance, threshold, ptau, workDir, snarkjs);

        // snarkjs CLI verification
        assertTrue(snarkjs.groth16Verify(workDir));

        // Pure Java off-chain verification
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                proof.proofJson(), proof.vkJson(), proof.publicJson(),
                new CircuitId("balance-threshold"));
        var material = VerificationMaterial.of(
                proof.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("balance-threshold"));

        var result = new Groth16BLS12381PureJavaVerifier().verify(envelope, material);
        assertTrue(result.proofValid(), "Proof should be valid: " + result);

        // Public vars: [threshold, isAboveThreshold]
        var publicInputs = SnarkjsJsonCodec.parsePublicInputs(proof.publicJson());
        assertEquals(2, publicInputs.size());
        assertEquals(BigInteger.ONE, publicInputs.get(1),
                "isAboveThreshold should be 1");
    }

    @Test
    void groth16_bls12381_balanceBelowThreshold(@TempDir Path workDir) throws Exception {
        var helper = new BalanceThresholdProofHelper(CurveId.BLS12_381);

        var balance = BigInteger.valueOf(1_000);
        var threshold = BigInteger.valueOf(5_000);

        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
        var proof = helper.generateGroth16Proof(balance, threshold, ptau, workDir, snarkjs);

        assertTrue(snarkjs.groth16Verify(workDir));

        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                proof.proofJson(), proof.vkJson(), proof.publicJson(),
                new CircuitId("balance-threshold"));
        var material = VerificationMaterial.of(
                proof.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("balance-threshold"));

        var result = new Groth16BLS12381PureJavaVerifier().verify(envelope, material);
        assertTrue(result.proofValid());

        var publicInputs = SnarkjsJsonCodec.parsePublicInputs(proof.publicJson());
        assertEquals(BigInteger.ZERO, publicInputs.get(1),
                "isAboveThreshold should be 0 for balance below threshold");
    }

    /**
     * Demonstrates verifier reusability: same Groth16BLS12381PureJavaVerifier verifies
     * proofs from DIFFERENT circuits — only the VK changes.
     */
    @Test
    void sameVerifier_differentCircuits(@TempDir Path workDir) throws Exception {
        var verifier = new Groth16BLS12381PureJavaVerifier();
        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);

        // --- Circuit 1: BalanceThreshold ---
        var balanceDir = workDir.resolve("balance");
        java.nio.file.Files.createDirectories(balanceDir);

        var balanceHelper = new BalanceThresholdProofHelper(CurveId.BLS12_381);
        var balanceProof = balanceHelper.generateGroth16Proof(
                BigInteger.valueOf(10_000), BigInteger.valueOf(5_000),
                ptau, balanceDir, snarkjs);

        var balanceEnvelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                balanceProof.proofJson(), balanceProof.vkJson(), balanceProof.publicJson(),
                new CircuitId("balance-threshold"));
        var balanceMaterial = VerificationMaterial.of(
                balanceProof.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("balance-threshold"));

        assertTrue(verifier.verify(balanceEnvelope, balanceMaterial).proofValid(),
                "Balance proof should verify with balance VK");

        // --- Circuit 2: SealedBid (different circuit, SAME verifier) ---
        var bidDir = workDir.resolve("bid");
        java.nio.file.Files.createDirectories(bidDir);

        var bidHelper = new com.bloxbean.cardano.zeroj.examples.dsl.auction.SealedBidProofHelper(CurveId.BLS12_381);
        var bidProof = bidHelper.generateGroth16Proof(
                BigInteger.valueOf(1000), BigInteger.valueOf(42), BigInteger.valueOf(500),
                ptau, bidDir, snarkjs);

        var bidEnvelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                bidProof.proofJson(), bidProof.vkJson(), bidProof.publicJson(),
                new CircuitId("sealed-bid"));
        var bidMaterial = VerificationMaterial.of(
                bidProof.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("sealed-bid"));

        assertTrue(verifier.verify(bidEnvelope, bidMaterial).proofValid(),
                "Bid proof should verify with bid VK — SAME verifier, different VK");

        // --- Cross-circuit verification must FAIL ---
        var crossResult = verifier.verify(balanceEnvelope, bidMaterial);
        assertFalse(crossResult.proofValid(),
                "Balance proof should NOT verify with bid VK (different circuit)");
    }
}
