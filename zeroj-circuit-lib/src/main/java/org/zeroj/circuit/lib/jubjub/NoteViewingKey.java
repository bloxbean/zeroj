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
