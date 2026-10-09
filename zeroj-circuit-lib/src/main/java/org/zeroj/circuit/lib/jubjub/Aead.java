package org.zeroj.circuit.lib.jubjub;

import java.security.GeneralSecurityException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8) on the JDK's provider, shared by
 * {@code dkg-share-delivery-hpke-v1} (ADR-0054, through {@link Hpke}) and
 * {@code confidential-note-jubjub-v1} (ADR-0055, through {@link SaplingNoteCrypto}).
 *
 * <p>The lookup names the algorithm only, never a provider. A GraalVM native image registers a
 * provider only when an algorithm-only lookup reaches it (ADR-0054 implementation note 10).
 * Callers classify failures: {@link javax.crypto.AEADBadTagException} is a property of the input;
 * anything else is a fault of the platform.
 */
final class Aead {

    static final int KEY_LENGTH = 32;
    static final int NONCE_LENGTH = 12;
    static final int TAG_LENGTH = 16;

    private Aead() {
    }

    /**
     * Encrypts ({@link Cipher#ENCRYPT_MODE}) or decrypts ({@link Cipher#DECRYPT_MODE}) with a
     * 32-byte key and a 12-byte nonce. Decryption returns the plaintext only if the tag verifies.
     */
    static byte[] chacha20Poly1305(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input)
            throws GeneralSecurityException {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(nonce, "nonce");
        Objects.requireNonNull(aad, "aad");
        Objects.requireNonNull(input, "input");
        if (key.length != KEY_LENGTH || nonce.length != NONCE_LENGTH) {
            throw new IllegalArgumentException("ChaCha20-Poly1305 needs a 32-byte key and a 12-byte nonce");
        }
        Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        if (aad.length > 0) cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }
}
