package com.bloxbean.cardano.zeroj.examples.dsl.voting;

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
 * E2E test: AnonymousVotingCircuit → snarkjs Groth16 → off-chain Java verify.
 */
@Tag("e2e")
class AnonymousVotingE2ETest {

    private static SnarkjsProver snarkjs;

    @BeforeAll
    static void checkPrerequisites() {
        snarkjs = new SnarkjsProver();
        assumeTrue(snarkjs.isAvailable(), "snarkjs not found — skipping E2E tests");
    }

    @Test
    void groth16_bls12381_voteYes(@TempDir Path workDir) throws Exception {
        var helper = new AnonymousVotingProofHelper(CurveId.BLS12_381);

        var vote = BigInteger.ONE;         // vote = YES
        var nullifier = BigInteger.valueOf(12345);

        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
        var proof = helper.generateGroth16Proof(vote, nullifier, ptau, workDir, snarkjs);

        // snarkjs CLI verification
        assertTrue(snarkjs.groth16Verify(workDir));

        // Pure Java off-chain verification
        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                proof.proofJson(), proof.vkJson(), proof.publicJson(),
                new CircuitId("anonymous-vote"));
        var material = VerificationMaterial.of(
                proof.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("anonymous-vote"));

        var result = new Groth16BLS12381PureJavaVerifier().verify(envelope, material);
        assertTrue(result.proofValid(), "Proof should be valid: " + result);

        // The public output is the commitment (1 public var)
        var publicInputs = SnarkjsJsonCodec.parsePublicInputs(proof.publicJson());
        assertEquals(1, publicInputs.size(), "Should have 1 public input (commitment)");

        // Verify commitment matches what we'd compute standalone
        var expectedCommitment = helper.computeCommitment(vote, nullifier);
        assertEquals(expectedCommitment, publicInputs.get(0),
                "Public commitment should match standalone MiMC computation");
    }

    @Test
    void groth16_bls12381_voteNo(@TempDir Path workDir) throws Exception {
        var helper = new AnonymousVotingProofHelper(CurveId.BLS12_381);

        var vote = BigInteger.ZERO;        // vote = NO
        var nullifier = BigInteger.valueOf(67890);

        Path ptau = snarkjs.powersOfTau("bls12-381", 13, workDir);
        var proof = helper.generateGroth16Proof(vote, nullifier, ptau, workDir, snarkjs);

        assertTrue(snarkjs.groth16Verify(workDir));

        var envelope = SnarkjsJsonCodec.toEnvelopeFromJson(
                proof.proofJson(), proof.vkJson(), proof.publicJson(),
                new CircuitId("anonymous-vote"));
        var material = VerificationMaterial.of(
                proof.vkJson().getBytes(StandardCharsets.UTF_8),
                ProofSystemId.GROTH16, CurveId.BLS12_381, new CircuitId("anonymous-vote"));

        var result = new Groth16BLS12381PureJavaVerifier().verify(envelope, material);
        assertTrue(result.proofValid());
    }
}
