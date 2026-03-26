package com.bloxbean.cardano.zeroj.yaci.protocol;

import java.security.*;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Objects;

/**
 * Ed25519 signature utilities for submission signing and verification.
 *
 * <p>Uses Java's built-in EdDSA support (available since Java 15).</p>
 */
public final class Ed25519Signer {

    private Ed25519Signer() {}

    /**
     * Generate a new Ed25519 key pair (for testing and development).
     */
    public static KeyPair generateKeyPair() {
        try {
            var kpg = KeyPairGenerator.getInstance("Ed25519");
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Ed25519 not available", e);
        }
    }

    /**
     * Sign a message with an Ed25519 private key.
     *
     * @param message    the message to sign
     * @param privateKey the Ed25519 private key
     * @return the 64-byte Ed25519 signature
     */
    public static byte[] sign(byte[] message, PrivateKey privateKey) {
        Objects.requireNonNull(message, "message must not be null");
        Objects.requireNonNull(privateKey, "privateKey must not be null");
        try {
            var sig = Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(message);
            return sig.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Ed25519 signing failed", e);
        }
    }

    /**
     * Verify an Ed25519 signature.
     *
     * @param message   the original message
     * @param signature the 64-byte signature to verify
     * @param publicKey the Ed25519 public key
     * @return true if the signature is valid
     */
    public static boolean verify(byte[] message, byte[] signature, PublicKey publicKey) {
        Objects.requireNonNull(message, "message must not be null");
        Objects.requireNonNull(signature, "signature must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        try {
            var sig = Signature.getInstance("Ed25519");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(signature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            return false;
        }
    }

    /**
     * Extract the raw 32-byte public key from a Java PublicKey.
     */
    public static byte[] publicKeyBytes(PublicKey publicKey) {
        // Ed25519 public keys are encoded as X.509 SubjectPublicKeyInfo
        // The raw 32-byte key is at the end of the encoded form
        byte[] encoded = publicKey.getEncoded();
        byte[] raw = new byte[32];
        System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
        return raw;
    }

    /**
     * Sign a submission (signs the deterministic submission hash).
     */
    public static byte[] signSubmission(AppProofSubmission submission, PrivateKey privateKey) {
        byte[] hash = SubmissionHash.compute(submission);
        return sign(hash, privateKey);
    }

    /**
     * Verify a submission signature.
     */
    public static boolean verifySubmission(AppProofSubmission submission, PublicKey publicKey) {
        byte[] hash = SubmissionHash.compute(submission);
        return verify(hash, submission.submitterSignature(), publicKey);
    }
}
