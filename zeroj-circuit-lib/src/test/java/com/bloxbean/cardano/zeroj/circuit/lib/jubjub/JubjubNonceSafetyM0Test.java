package com.bloxbean.cardano.zeroj.circuit.lib.jubjub;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * ADR-0039 M0 regression fixtures for catastrophic nonce failures.
 *
 * <p>These tests deliberately demonstrate the recovery equations. They are not alternate
 * signing implementations and must never become production entry points.
 */
class JubjubNonceSafetyM0Test {

    private static final BigInteger L = JubjubCurve.SUBGROUP_ORDER;
    private static final BigInteger SK = new BigInteger(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd", 16)
            .mod(L);

    @Test
    @DisplayName("compatibility signing fails closed on the catastrophic zero nonce")
    void zeroNonceIsRejectedBeforeSigningCanContinue() {
        EdDSAJubjub.Keypair keypair = EdDSAJubjub.keypairFromSecret(SK);
        AtomicInteger multiplications = new AtomicInteger();
        JubjubPoint.installSecretScheduleObserverForTesting(
                new JubjubPoint.SecretScheduleObserver() {
                    @Override
                    public void scheduleStarted(int iterations) {
                        multiplications.incrementAndGet();
                    }

                    @Override
                    public void addition() {
                    }

                    @Override
                    public void doubling() {
                    }
                });
        try {
            assertThrows(IllegalStateException.class,
                    () -> EdDSAJubjub.completeWithDerivedNonceForTesting(
                            keypair, BigInteger.ONE, BigInteger.ZERO));
            assertEquals(0, multiplications.get(),
                    "zero nonce must fail before secret point multiplication");
        } finally {
            JubjubPoint.clearSecretScheduleObserverForTesting();
        }

        assertEquals(BigInteger.ONE, EdDSAJubjub.requireNonZeroNonce(BigInteger.ONE));
        assertThrows(NullPointerException.class,
                () -> EdDSAJubjub.requireNonZeroNonce(null));
    }

    @Test
    @DisplayName("a released zero-nonce signature directly reveals the secret key")
    void zeroNonceRecoveryEquation() {
        BigInteger message = BigInteger.valueOf(7);
        JubjubPoint publicKey = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(SK);
        JubjubPoint rPoint = JubjubPoint.IDENTITY;
        BigInteger challenge = EdDSAJubjub.computeChallenge(rPoint, publicKey, message);
        if (challenge.signum() == 0) {
            throw new AssertionError("fixture challenge unexpectedly zero");
        }

        // With r=0, S = k*sk. Everything on the right except sk is public.
        BigInteger s = challenge.multiply(SK).mod(L);
        BigInteger recovered = s.multiply(challenge.modInverse(L)).mod(L);
        assertEquals(SK, recovered);
    }

    @Test
    @DisplayName("reusing a nonce across two messages reveals the secret key")
    void repeatedNonceRecoveryEquation() {
        BigInteger nonce = BigInteger.valueOf(0x5eed);
        JubjubPoint publicKey = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(SK);
        JubjubPoint rPoint = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(nonce);
        BigInteger k1 = EdDSAJubjub.computeChallenge(rPoint, publicKey, BigInteger.valueOf(11));
        BigInteger k2 = EdDSAJubjub.computeChallenge(rPoint, publicKey, BigInteger.valueOf(12));
        if (k1.equals(k2)) {
            throw new AssertionError("fixture challenges unexpectedly equal");
        }

        BigInteger s1 = nonce.add(k1.multiply(SK)).mod(L);
        BigInteger s2 = nonce.add(k2.multiply(SK)).mod(L);
        BigInteger recovered = s1.subtract(s2).mod(L)
                .multiply(k1.subtract(k2).mod(L).modInverse(L))
                .mod(L);
        assertEquals(SK, recovered);
    }

    @Test
    @DisplayName("a publicly known nonce reveals the secret key from one signature")
    void publicNonceRecoveryEquation() {
        BigInteger nonce = BigInteger.valueOf(123_456);
        BigInteger message = BigInteger.valueOf(99);
        JubjubPoint publicKey = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(SK);
        JubjubPoint rPoint = JubjubPoint.SUBGROUP_GENERATOR.scalarMul(nonce);
        BigInteger challenge = EdDSAJubjub.computeChallenge(rPoint, publicKey, message);
        if (challenge.signum() == 0) {
            throw new AssertionError("fixture challenge unexpectedly zero");
        }

        BigInteger s = nonce.add(challenge.multiply(SK)).mod(L);
        BigInteger recovered = s.subtract(nonce).mod(L)
                .multiply(challenge.modInverse(L))
                .mod(L);
        assertEquals(SK, recovered);
    }
}
