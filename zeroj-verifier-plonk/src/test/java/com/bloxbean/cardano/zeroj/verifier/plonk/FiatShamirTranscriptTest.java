package com.bloxbean.cardano.zeroj.verifier.plonk;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the Keccak-256 Fiat-Shamir transcript.
 */
class FiatShamirTranscriptTest {

    private static final BigInteger BN254_R = new BigInteger(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617");

    private static final BigInteger BLS12_381_R = new BigInteger(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16);

    @Test
    void deterministic_sameInputsSameChallenge() {
        var t1 = new FiatShamirTranscript(BN254_R);
        var t2 = new FiatShamirTranscript(BN254_R);
        t1.addScalar(BigInteger.valueOf(42));
        t2.addScalar(BigInteger.valueOf(42));
        assertEquals(t1.getChallenge(), t2.getChallenge());
    }

    @Test
    void differentInputs_differentChallenge() {
        var t1 = new FiatShamirTranscript(BN254_R);
        var t2 = new FiatShamirTranscript(BN254_R);
        t1.addScalar(BigInteger.valueOf(42));
        t2.addScalar(BigInteger.valueOf(43));
        assertNotEquals(t1.getChallenge(), t2.getChallenge());
    }

    @Test
    void challengeIsInField() {
        var t = new FiatShamirTranscript(BN254_R);
        t.addScalar(BigInteger.valueOf(12345));
        BigInteger c = t.getChallenge();
        assertTrue(c.signum() >= 0);
        assertTrue(c.compareTo(BN254_R) < 0);
    }

    @Test
    void squeezeNonZeroChallenge_isNonZero() {
        var t = new FiatShamirTranscript(BN254_R);
        t.addScalar(BigInteger.TEN);
        BigInteger c = t.squeezeNonZeroChallenge();
        assertTrue(c.signum() > 0);
    }

    @Test
    void reset_clearsState() {
        var t1 = new FiatShamirTranscript(BN254_R);
        t1.addScalar(BigInteger.valueOf(999));
        t1.getChallenge();
        t1.reset();

        var t2 = new FiatShamirTranscript(BN254_R);
        t1.addScalar(BigInteger.valueOf(42));
        t2.addScalar(BigInteger.valueOf(42));
        assertEquals(t1.getChallenge(), t2.getChallenge());
    }

    @Test
    void appendG1Point_affectsChallenge() {
        var t1 = new FiatShamirTranscript(BN254_R);
        var t2 = new FiatShamirTranscript(BN254_R);
        t1.addPolCommitment(BigInteger.ONE, BigInteger.TWO);
        t2.addPolCommitment(BigInteger.ONE, BigInteger.valueOf(3));
        assertNotEquals(t1.getChallenge(), t2.getChallenge());
    }

    @Test
    void appendBytes_affectsChallenge() {
        var t1 = new FiatShamirTranscript(BN254_R);
        var t2 = new FiatShamirTranscript(BN254_R);
        t1.appendBytes(new byte[]{1, 2, 3});
        t2.appendBytes(new byte[]{1, 2, 4});
        assertNotEquals(t1.getChallenge(), t2.getChallenge());
    }

    @Test
    void bls12381_challengeInField() {
        var t = new FiatShamirTranscript(BLS12_381_R, 32, 48);
        t.addScalar(BigInteger.valueOf(12345));
        BigInteger c = t.getChallenge();
        assertTrue(c.signum() >= 0);
        assertTrue(c.compareTo(BLS12_381_R) < 0);
    }

    @Test
    void multiRound_resetBetweenRounds() {
        var t = new FiatShamirTranscript(BN254_R);

        // Round 1
        t.addScalar(BigInteger.ONE);
        BigInteger c1 = t.getChallenge();

        // Round 2 (reset and seed with c1)
        t.reset();
        t.addScalar(c1);
        BigInteger c2 = t.getChallenge();

        assertNotEquals(c1, c2, "different rounds should produce different challenges");
        assertTrue(c2.compareTo(BN254_R) < 0);
    }

    @Test
    void plonkChallengeSequence_sixRounds() {
        var t = new FiatShamirTranscript(BN254_R);

        // Round 1: commitments → beta
        t.addPolCommitment(BigInteger.valueOf(111), BigInteger.valueOf(222));
        t.addPolCommitment(BigInteger.valueOf(333), BigInteger.valueOf(444));
        BigInteger beta = t.getChallenge();

        // Round 2: reset, seed with beta → gamma
        t.reset();
        t.addScalar(beta);
        BigInteger gamma = t.getChallenge();

        // Round 3: reset, seed with beta+gamma → alpha
        t.reset();
        t.addScalar(beta);
        t.addScalar(gamma);
        t.addPolCommitment(BigInteger.ONE, BigInteger.TWO);
        BigInteger alpha = t.getChallenge();

        // Round 4: reset → xi
        t.reset();
        t.addScalar(alpha);
        t.addPolCommitment(BigInteger.ONE, BigInteger.TWO);
        BigInteger xi = t.getChallenge();

        // Round 5: reset → v
        t.reset();
        t.addScalar(xi);
        t.addScalar(BigInteger.TEN);
        BigInteger v = t.getChallenge();

        // Round 6: reset → u
        t.reset();
        t.addPolCommitment(BigInteger.ONE, BigInteger.TWO);
        BigInteger u = t.getChallenge();

        var challenges = java.util.List.of(beta, gamma, alpha, xi, v, u);
        for (var c : challenges) {
            assertTrue(c.signum() > 0);
            assertTrue(c.compareTo(BN254_R) < 0);
        }
        assertEquals(6, new java.util.HashSet<>(challenges).size(), "all 6 should be unique");
    }
}
