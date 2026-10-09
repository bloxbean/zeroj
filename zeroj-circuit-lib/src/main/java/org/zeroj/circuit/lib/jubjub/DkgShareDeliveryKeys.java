package org.zeroj.circuit.lib.jubjub;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * One participant's encryption key pair for one key-generation attempt
 * ({@code dkg-share-delivery-hpke-v1} §2.3, §7; ADR-0054 D5).
 *
 * <ul>
 *   <li><b>Per attempt.</b> The pair is bound to the session it was generated for. It refuses
 *       to open envelopes of any other session.</li>
 *   <li><b>Separate.</b> It is never the roster authentication key and is not derived from
 *       it.</li>
 *   <li><b>Destroyable.</b> {@link #destroy()} wipes the private key, and opening is refused
 *       afterwards. {@link DkgShareDelivery#closeRound1} destroys it once round 1 is processed.
 *       Java cannot guarantee erasure, so this is best effort: compatibility/offline class
 *       (ADR-0039 §3.1). Copies outside this class's control include the provider's
 *       {@code XECPrivateKey} built for each {@code closeRound1}, the HKDF and AEAD
 *       {@code SecretKeySpec}s, and the JDK {@code KDF} and {@code Cipher} internals; on JDK 25
 *       their {@code destroy()} is not supported.</li>
 * </ul>
 */
public final class DkgShareDeliveryKeys {

    private final DkgConfig config;
    private final int id;
    private final byte[] secret;
    private final byte[] publicKey;
    private boolean destroyed;

    private DkgShareDeliveryKeys(DkgConfig config, int id, byte[] secret, byte[] publicKey) {
        this.config = config;
        this.id = id;
        this.secret = secret;
        this.publicKey = publicKey;
    }

    /** A fresh key pair for participant {@code id} of this configuration's session. */
    public static DkgShareDeliveryKeys generate(DkgConfig config, int id, SecureRandom random) {
        Objects.requireNonNull(random, "random");
        byte[] secret = new byte[Hpke.N_SK];
        random.nextBytes(secret);
        try {
            return fromSecret(config, id, secret);
        } finally {
            Arrays.fill(secret, (byte) 0); // fromSecret keeps its own copy
        }
    }

    /** Test seam: a key pair from a given private key (spec §9.1 test keys). */
    static DkgShareDeliveryKeys fromSecret(DkgConfig config, int id, byte[] secret) {
        Objects.requireNonNull(config, "config");
        config.requireParticipant(id);
        if (secret == null || secret.length != Hpke.N_SK) {
            throw new IllegalArgumentException("an X25519 private key is 32 bytes");
        }
        try {
            return new DkgShareDeliveryKeys(config, id, secret.clone(), X25519Bytes.publicFromPrivate(secret));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 is unavailable", e);
        }
    }

    /** The participant this pair belongs to. */
    public int id() {
        return id;
    }

    /** The configuration, and so the session, this pair is bound to. */
    public DkgConfig config() {
        return config;
    }

    /** {@code pkR}, 32 bytes. */
    public byte[] publicKey() {
        return publicKey.clone();
    }

    /** The round-0 announcement to post, authenticated under the roster key (spec §3.1). */
    public byte[] announcement() {
        return DkgShareDeliveryCodec.announcement(config, id, publicKey);
    }

    /** Wipes the private key; opening is refused afterwards. Idempotent. */
    public synchronized void destroy() {
        Arrays.fill(secret, (byte) 0);
        destroyed = true;
    }

    /** {@code true} once {@link #destroy()} has run. */
    public synchronized boolean isDestroyed() {
        return destroyed;
    }

    /** The private key for opening under {@code session}, or an exception if refused. */
    synchronized byte[] secretFor(DkgConfig session) {
        if (destroyed) {
            throw new IllegalStateException("the delivery keys have been destroyed");
        }
        if (!config.equals(session)) {
            throw new IllegalArgumentException("the delivery keys belong to another session");
        }
        return secret.clone();
    }

    @Override
    public String toString() {
        return "DkgShareDeliveryKeys{id=" + id + ", session=" + config + ", secret=<redacted>"
                + (destroyed ? ", destroyed" : "") + "}";
    }
}
