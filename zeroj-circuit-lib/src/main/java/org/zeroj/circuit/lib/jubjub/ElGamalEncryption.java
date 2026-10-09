package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;

/**
 * A freshly encrypted ciphertext together with its <b>opening</b> {@code (m, k)}, returned by
 * {@link ElGamal#encryptWithOpening} so that the encrypting party can prove the encryption
 * relation ({@code elgamal-jubjub-v1} §9.1).
 *
 * <p>The opening is secret: anyone who learns {@code k} can recover {@code m}. Use it only to
 * build the prover's witness, offline or in an isolated process (ADR-0039 compatibility/offline
 * class), and discard it. {@link #toString()} redacts it.
 */
public final class ElGamalEncryption {

    private final ElGamalCiphertext ciphertext;
    private final BigInteger message;
    private final BigInteger randomness;
    private final int width;

    ElGamalEncryption(ElGamalCiphertext ciphertext, BigInteger message, BigInteger randomness, int width) {
        this.ciphertext = ciphertext;
        this.message = message;
        this.randomness = randomness;
        this.width = width;
    }

    /** The admitted ciphertext. */
    public ElGamalCiphertext ciphertext() {
        return ciphertext;
    }

    /** The message {@code m}: a witness value. */
    public BigInteger message() {
        return message;
    }

    /** The randomness {@code k}: a witness value that must stay secret. */
    public BigInteger randomness() {
        return randomness;
    }

    /** The width the message was encrypted at. */
    public int width() {
        return width;
    }

    /** The encryption statement the proof must establish: the joint key, {@code A}, {@code B}. */
    public EncryptionStatement statement() {
        return new EncryptionStatement(ciphertext.context().jointKey(),
                ciphertext.handle(), ciphertext.blinded(), width);
    }

    @Override
    public String toString() {
        return "ElGamalEncryption{ciphertext=" + ciphertext + ", width=" + width + ", opening=<redacted>}";
    }
}
