package com.bloxbean.cardano.zeroj.verifier.plonk;

import com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkCodec;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.Fp;
import com.bloxbean.cardano.zeroj.verifier.groth16.bn254.G1Point;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies that our Fiat-Shamir transcript produces the exact same challenges as snarkjs.
 * Expected values extracted from snarkjs PlonK verifier with debug logging enabled.
 */
class SnarkjsTranscriptCompatTest {

    private static final BigInteger Fr = G1Point.R;

    // Expected challenge values from snarkjs debug output
    private static final BigInteger EXPECTED_BETA = new BigInteger("26ba59b2a21f21dacf495458c4aad0b177c83c160b015606f42d67abe6c9ed1e", 16);
    private static final BigInteger EXPECTED_GAMMA = new BigInteger("10666eaa348d0004649bb252e093b965ac7fb4b1fd6fd685fe38417ebf04d82c", 16);
    private static final BigInteger EXPECTED_ALPHA = new BigInteger("1a1ce0e72e667627518fec8c8e999da6b06b5213381b32a06012a9ce3e3ec47", 16);
    private static final BigInteger EXPECTED_XI = new BigInteger("ef2f8b229f033564131c33a6d616a7af46455c8f3b97ab61dc5027fd4dbe96c", 16);
    private static final BigInteger EXPECTED_V1 = new BigInteger("958affd35e56ef84099dbf7d85580740bd009591d98a443df81edb35b20beea", 16);
    private static final BigInteger EXPECTED_U = new BigInteger("da833c2d2cfeedddca6c87c7f59e645e5efe5ae4b702c101bfb2f9ad987636", 16);

    private com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkProof proof;
    private com.bloxbean.cardano.zeroj.codec.SnarkjsPlonkVerificationKey vk;
    private BigInteger[] publicSignals;

    @BeforeEach
    void setUp() {
        proof = SnarkjsPlonkCodec.parseProof(loadResource("/test-vectors/plonk-bn254/proof.json"));
        vk = SnarkjsPlonkCodec.parseVerificationKey(loadResource("/test-vectors/plonk-bn254/verification_key.json"));
        var inputs = com.bloxbean.cardano.zeroj.codec.SnarkjsJsonCodec.parsePublicInputs(
                loadResource("/test-vectors/plonk-bn254/public.json"));
        publicSignals = inputs.values().toArray(BigInteger[]::new);
    }

    @Test
    void keccak256_knownVector() {
        // Test Keccak-256 against a known vector: empty input
        byte[] empty = Keccak256.hash(new byte[0]);
        assertEquals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                hex(empty), "Keccak-256 of empty input must match Ethereum/snarkjs");
    }

    @Test
    void keccak256_helloWorld() {
        byte[] result = Keccak256.hash("hello".getBytes(StandardCharsets.UTF_8));
        assertEquals("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
                hex(result));
    }

    @Test
    void beta_matchesSnarkjs() {
        var transcript = new FiatShamirTranscript(Fr, 32, 32);

        // Round 2: VK commitments
        addG1FromCoords(transcript, vk.Qm());
        addG1FromCoords(transcript, vk.Ql());
        addG1FromCoords(transcript, vk.Qr());
        addG1FromCoords(transcript, vk.Qo());
        addG1FromCoords(transcript, vk.Qc());
        addG1FromCoords(transcript, vk.S1());
        addG1FromCoords(transcript, vk.S2());
        addG1FromCoords(transcript, vk.S3());

        // Public signals
        for (BigInteger pub : publicSignals) {
            transcript.addScalar(pub);
        }

        // Proof A, B, C
        addG1FromCoords(transcript, proof.A());
        addG1FromCoords(transcript, proof.B());
        addG1FromCoords(transcript, proof.C());

        BigInteger beta = transcript.getChallenge();
        assertEquals(EXPECTED_BETA, beta, "beta must match snarkjs");
    }

    @Test
    void gamma_matchesSnarkjs() {
        // First derive beta (same as above)
        var transcript = new FiatShamirTranscript(Fr, 32, 32);
        addG1FromCoords(transcript, vk.Qm()); addG1FromCoords(transcript, vk.Ql());
        addG1FromCoords(transcript, vk.Qr()); addG1FromCoords(transcript, vk.Qo());
        addG1FromCoords(transcript, vk.Qc()); addG1FromCoords(transcript, vk.S1());
        addG1FromCoords(transcript, vk.S2()); addG1FromCoords(transcript, vk.S3());
        for (BigInteger pub : publicSignals) transcript.addScalar(pub);
        addG1FromCoords(transcript, proof.A()); addG1FromCoords(transcript, proof.B());
        addG1FromCoords(transcript, proof.C());
        BigInteger beta = transcript.getChallenge();

        // gamma: reset, add beta
        transcript.reset();
        transcript.addScalar(beta);
        BigInteger gamma = transcript.getChallenge();
        assertEquals(EXPECTED_GAMMA, gamma, "gamma must match snarkjs");
    }

    @Test
    void allChallenges_matchSnarkjs() {
        var transcript = new FiatShamirTranscript(Fr, 32, 32);

        // beta
        addG1FromCoords(transcript, vk.Qm()); addG1FromCoords(transcript, vk.Ql());
        addG1FromCoords(transcript, vk.Qr()); addG1FromCoords(transcript, vk.Qo());
        addG1FromCoords(transcript, vk.Qc()); addG1FromCoords(transcript, vk.S1());
        addG1FromCoords(transcript, vk.S2()); addG1FromCoords(transcript, vk.S3());
        for (BigInteger pub : publicSignals) transcript.addScalar(pub);
        addG1FromCoords(transcript, proof.A()); addG1FromCoords(transcript, proof.B());
        addG1FromCoords(transcript, proof.C());
        BigInteger beta = transcript.getChallenge();
        assertEquals(EXPECTED_BETA, beta, "beta");

        // gamma
        transcript.reset();
        transcript.addScalar(beta);
        BigInteger gamma = transcript.getChallenge();
        assertEquals(EXPECTED_GAMMA, gamma, "gamma");

        // alpha
        transcript.reset();
        transcript.addScalar(beta); transcript.addScalar(gamma);
        addG1FromCoords(transcript, proof.Z());
        BigInteger alpha = transcript.getChallenge();
        assertEquals(EXPECTED_ALPHA, alpha, "alpha");

        // xi
        transcript.reset();
        transcript.addScalar(alpha);
        addG1FromCoords(transcript, proof.T1()); addG1FromCoords(transcript, proof.T2());
        addG1FromCoords(transcript, proof.T3());
        BigInteger xi = transcript.getChallenge();
        assertEquals(EXPECTED_XI, xi, "xi");

        // v
        transcript.reset();
        transcript.addScalar(xi);
        transcript.addScalar(proof.evalA()); transcript.addScalar(proof.evalB());
        transcript.addScalar(proof.evalC()); transcript.addScalar(proof.evalS1());
        transcript.addScalar(proof.evalS2()); transcript.addScalar(proof.evalZw());
        BigInteger v1 = transcript.getChallenge();
        assertEquals(EXPECTED_V1, v1, "v[1]");

        // u
        transcript.reset();
        addG1FromCoords(transcript, proof.Wxi()); addG1FromCoords(transcript, proof.Wxiw());
        BigInteger u = transcript.getChallenge();
        assertEquals(EXPECTED_U, u, "u");
    }

    // --- Helpers ---

    /**
     * Add a G1 point from snarkjs projective [x, y, z] coordinates.
     * Converts to affine first, then adds to transcript.
     */
    private void addG1FromCoords(FiatShamirTranscript t, java.util.List<BigInteger> coords) {
        var pt = com.bloxbean.cardano.zeroj.verifier.groth16.bn254.G1Point.fromProjective(
                coords.get(0), coords.get(1), coords.size() > 2 ? coords.get(2) : BigInteger.ONE);
        if (pt.isInfinity()) {
            t.addPolCommitment(BigInteger.ZERO, BigInteger.ZERO);
        } else {
            t.addPolCommitment(pt.x().value(), pt.y().value());
        }
    }

    private String loadResource(String path) {
        try (var in = getClass().getResourceAsStream(path)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    private static String hex(byte[] bytes) {
        var sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
