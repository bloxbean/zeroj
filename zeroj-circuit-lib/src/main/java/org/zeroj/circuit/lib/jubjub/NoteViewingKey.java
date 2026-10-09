package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * A reader's viewing key pair for {@code confidential-note-jubjub-v1}: the secret
 * {@code sk ∈ [1, l)} and its {@link NoteReaderKey} {@code [sk]·G} (ADR-0055 D2; spec §2).
 *
 * <p><b>Key separation (ADR-0055 I6).</b> A viewing key decrypts note deliveries and nothing
 * else. It is not an {@code elgamal-jubjub-v1} key, an EdDSA key or a spending key, and cannot
 * be converted to or from one.
 *
 * <p><b>Compatibility/offline class (ADR-0039 §3.1).</b> Generation and every decryption
 * multiply by {@code sk} with variable-time {@code BigInteger} arithmetic through the blinded
 * best-effort schedule. Scan only in the user's own wallet process, never as a shared or
 * network-facing service (ADR-0055 D9). No method makes a constant-time claim.
 *
 * <p><b>Lifetime.</b> {@link #destroy()} wipes the stored bytes and makes every later use throw.
 * Copies made during earlier operations (as {@code BigInteger}) cannot be wiped. Anyone who
 * later obtains the secret reads every delivery ever made to this key (ADR-0055 threat model).
 */
public final class NoteViewingKey {

    private final byte[] secret; // I2OSP(sk, 32)
    private final NoteReaderKey readerKey;
    private boolean destroyed;

    private NoteViewingKey(BigInteger sk) {
        this.secret = DkgMessage.i2osp32(sk);
        this.readerKey = NoteReaderKey.ofValidated(SaplingNoteCrypto.derivePublic(sk));
    }

    /**
     * Samples a viewing key: 64 random bytes reduced mod {@code l}, resampled while zero
     * (spec §2.1).
     *
     * @param random a cryptographically secure source
     */
    public static NoteViewingKey generate(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        while (true) {
            BigInteger candidate = ElGamal.sample(random);
            if (candidate.signum() != 0) {
                return new NoteViewingKey(candidate);
            }
        }
    }

    /**
     * Restores a viewing key from the 32-byte secret {@link #exportSecret()} produced, so that
     * notes delivered earlier can be read after a restart (ADR-0055 D2: old generations stay
     * readable only while their key is kept). The caller's array is not retained; wipe it after use.
     *
     * @throws IllegalArgumentException unless {@code secret} is exactly 32 bytes encoding
     *         {@code 1 ≤ sk < l} (big-endian, {@code I2OSP(sk, 32)})
     */
    public static NoteViewingKey restore(byte[] secret) {
        Objects.requireNonNull(secret, "secret");
        if (secret.length != 32) {
            throw new IllegalArgumentException("a viewing-key secret is exactly 32 bytes");
        }
        BigInteger sk = new BigInteger(1, secret);
        if (sk.signum() == 0 || sk.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("a viewing-key secret must encode 1 <= sk < l");
        }
        return new NoteViewingKey(sk);
    }

    /**
     * The secret as 32 bytes, {@code I2OSP(sk, 32)}, for the wallet's own encrypted key storage.
     * The caller owns the copy and must wipe it after storing it. Anyone who obtains these bytes
     * reads every note ever delivered to this key.
     *
     * @throws IllegalStateException once destroyed
     */
    public synchronized byte[] exportSecret() {
        if (destroyed) {
            throw new IllegalStateException("the viewing key has been destroyed");
        }
        return secret.clone();
    }

    /**
     * Proves possession of this key for registration (spec §2.2; ADR-0055 Q6). The application's
     * DLEQ prover receives the statement ({@code X = G}, {@code P = D = readerKey}) and the
     * witness {@code sk}, for that call only, and returns its proof. The prover runs in the
     * wallet's own process (ADR-0039 offline class) and must not retain the witness.
     *
     * @throws IllegalStateException once destroyed
     */
    public <T> T provePossession(PossessionProver<T> prover) {
        Objects.requireNonNull(prover, "prover");
        return prover.prove(possessionStatement(), secretScalar());
    }

    /** The application's DLEQ prover for {@link #provePossession}. */
    @FunctionalInterface
    public interface PossessionProver<T> {
        /** Returns a proof of {@code statement} with witness {@code secret}; must not retain {@code secret}. */
        T prove(DleqStatement statement, BigInteger secret);
    }

    /** Test seam: a key with a fixed secret (vectors only). */
    static NoteViewingKey fromSecret(BigInteger sk) {
        Objects.requireNonNull(sk, "sk");
        if (sk.signum() <= 0 || sk.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("a viewing secret must satisfy 1 <= sk < l");
        }
        return new NoteViewingKey(sk);
    }

    /** The public reader key {@code [sk]·G}, to publish or register. */
    public NoteReaderKey readerKey() {
        return readerKey;
    }

    /**
     * The possession statement for this key, to prove with the application's DLEQ prover when
     * registering it (spec §2.2).
     */
    public DleqStatement possessionStatement() {
        return readerKey.possessionStatement();
    }

    /** Wipes the secret; every later decryption throws {@link IllegalStateException}. Idempotent. */
    public synchronized void destroy() {
        Arrays.fill(secret, (byte) 0);
        destroyed = true;
    }

    /** {@code true} once {@link #destroy()} has run. */
    public synchronized boolean isDestroyed() {
        return destroyed;
    }

    /**
     * The secret scalar, rebuilt for one use.
     *
     * @throws IllegalStateException once destroyed
     */
    synchronized BigInteger secretScalar() {
        if (destroyed) {
            throw new IllegalStateException("the viewing key has been destroyed");
        }
        return new BigInteger(1, secret);
    }

    @Override
    public String toString() {
        return "NoteViewingKey{readerKey=" + readerKey + ", secret=<redacted>" + (isDestroyed() ? ", destroyed" : "") + "}";
    }
}
