package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * The three primitives of {@code confidential-note-jubjub-v1} (ADR-0055 D5; spec §1), as in Zcash
 * Sapling's in-band secret distribution:
 * <ul>
 *   <li>key agreement {@code KA.Agree(sk, X) = [8·sk]·X} (Zcash spec §5.4.5.3);</li>
 *   <li>the KDF {@code BLAKE2b-256(pers, encode(sharedSecret) ‖ E)} (§5.4.5.4);</li>
 *   <li>symmetric encryption: ChaCha20-Poly1305 with the all-zero nonce and empty associated
 *       data (§5.4.3).</li>
 * </ul>
 *
 * <p>The personalization is a parameter so that the Zcash Sapling vectors run through this code
 * with {@link #ZCASH_PERSONALIZATION} (ADR-0055 I10). The profile uses {@link #PERSONALIZATION}
 * only.
 *
 * <p><b>Secrets.</b> Scalars, shared secrets and keys are secret. Scalar multiplication uses the
 * blinded best-effort schedule on subgroup points only. Encoding a shared secret inverts its
 * projective {@code Z} with {@code BigInteger} arithmetic. Everything here is
 * compatibility/offline class (ADR-0039 §3.1), with no constant-time claim. Byte forms of secrets
 * are wiped after use, best effort.
 *
 * <p><b>Failures.</b> A failure caused by the input (a tag that does not verify, a wrong length,
 * an invalid point) is reported as {@code null}. A failure of the platform's provider is an
 * {@link IllegalStateException}, never "not mine" (spec §5).
 */
final class SaplingNoteCrypto {

    /** The profile's KDF personalization (spec §1; ADR-0055 Q1). */
    static final byte[] PERSONALIZATION = Hpke.ascii("ZeroJ_NoteKDF_v1");
    /** Zcash Sapling's KDF personalization, for conformance tests only. */
    static final byte[] ZCASH_PERSONALIZATION = Hpke.ascii("Zcash_SaplingKDF");

    static final int POINT_LENGTH = 32;
    static final int KEY_LENGTH = Aead.KEY_LENGTH;

    private static final byte[] ZERO_NONCE = new byte[Aead.NONCE_LENGTH];
    private static final byte[] NO_AAD = new byte[0];

    private SaplingNoteCrypto() {
    }

    /** {@code KA.DerivePublic(sk, G) = [sk]·G}, for {@code sk ∈ [1, l)}; normalized. */
    static JubjubPoint derivePublic(BigInteger sk) {
        requireNonZeroScalar(sk);
        return JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(sk).normalized();
    }

    /**
     * {@code KA.Agree(sk, X) = [8·sk]·X}. {@code X} must already be validated to lie in the
     * prime-order subgroup (the blinded schedule is defined only there). There, {@code [8·sk]·X}
     * equals {@code [(8·sk) mod l]·X}, so one blinded schedule computes it.
     */
    static JubjubPoint agree(BigInteger sk, JubjubPoint subgroupPoint) {
        requireNonZeroScalar(sk);
        Objects.requireNonNull(subgroupPoint, "subgroupPoint");
        BigInteger k = sk.shiftLeft(3).mod(SUBGROUP_ORDER);
        return subgroupPoint.scalarMulSecretBlindedBestEffort(k);
    }

    /**
     * {@code KDF(pers, sharedSecret, E) = BLAKE2b-256(pers, encode(sharedSecret) ‖ E)}, where
     * {@code ephemeralKey} is the 32-byte encoding <b>as received</b> (Zcash spec §4.20.2).
     */
    static byte[] kdf(byte[] personalization, JubjubPoint sharedSecret, byte[] ephemeralKey) {
        Objects.requireNonNull(personalization, "personalization");
        Objects.requireNonNull(sharedSecret, "sharedSecret");
        Objects.requireNonNull(ephemeralKey, "ephemeralKey");
        if (ephemeralKey.length != POINT_LENGTH) {
            throw new IllegalArgumentException("ephemeral key must be 32 bytes");
        }
        byte[] shared = sharedSecret.toBytes();
        byte[] input = new byte[2 * POINT_LENGTH];
        try {
            System.arraycopy(shared, 0, input, 0, POINT_LENGTH);
            System.arraycopy(ephemeralKey, 0, input, POINT_LENGTH, POINT_LENGTH);
            return Blake2bDigest.digest(input, KEY_LENGTH, personalization);
        } finally {
            Arrays.fill(shared, (byte) 0);
            Arrays.fill(input, (byte) 0);
        }
    }

    /**
     * {@code Sym.Encrypt}: ChaCha20-Poly1305 under {@code key}, zero nonce, no associated data.
     *
     * @throws IllegalStateException if the platform's provider fails
     */
    static byte[] encrypt(byte[] key, byte[] plaintext) {
        try {
            return Aead.chacha20Poly1305(Cipher.ENCRYPT_MODE, key, ZERO_NONCE, NO_AAD, plaintext);
        } catch (GeneralSecurityException | RuntimeException e) {
            throw platformFault(e);
        }
    }

    /**
     * {@code Sym.Decrypt}. Returns the plaintext, or {@code null} if the ciphertext is shorter
     * than a tag or its tag does not verify (a property of the input).
     *
     * @throws IllegalStateException if the platform's provider fails in any other way
     */
    static byte[] decrypt(byte[] key, byte[] ciphertext) {
        Objects.requireNonNull(ciphertext, "ciphertext");
        if (ciphertext.length < Aead.TAG_LENGTH) {
            return null;
        }
        try {
            return Aead.chacha20Poly1305(Cipher.DECRYPT_MODE, key, ZERO_NONCE, NO_AAD, ciphertext);
        } catch (AEADBadTagException notMine) {
            return null;
        } catch (GeneralSecurityException | RuntimeException e) {
            throw platformFault(e);
        }
    }

    /**
     * Decodes a received point that the profile requires to be a valid key (spec §2.2, §5 step
     * 2): canonical {@code pedersen-jubjub-v1} §4 encoding, in the prime-order subgroup, not the
     * identity. Returns the normalized point, or {@code null} for any failure; this is public data,
     * checked before any secret operation.
     */
    static JubjubPoint decodeKey(byte[] encoded) {
        if (encoded == null || encoded.length != POINT_LENGTH) {
            return null;
        }
        JubjubPoint point;
        try {
            point = JubjubPoint.fromBytes(encoded);
        } catch (IllegalArgumentException invalid) {
            return null;
        }
        if (point.isIdentity() || !FastJubjubPoint.isInPrimeOrderSubgroup(point)) {
            return null;
        }
        return point.normalized();
    }

    private static void requireNonZeroScalar(BigInteger k) {
        Objects.requireNonNull(k, "scalar");
        if (k.signum() <= 0 || k.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("secret scalar must satisfy 1 <= k < l");
        }
    }

    private static IllegalStateException platformFault(Exception e) {
        return new IllegalStateException("ChaCha20-Poly1305 failure (a platform fault, not a property of the input)", e);
    }
}
