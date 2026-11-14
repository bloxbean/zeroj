package org.zeroj.bls12381.bulletproofs;

import java.math.BigInteger;

/**
 * Where the prover's nonces come from (spec §7.3, §7.5). Package-private: published code has exactly
 * one implementation, {@link SystemNonceSource}. The deterministic test source lives only in the
 * unpublished test fixtures. No public or protected member of this package accepts a source, a
 * seed, a nonce or a {@code SecureRandom} ({@code BulletproofApiSurfaceTest}).
 */
interface NonceSource {

    /** The next nonce, uniform on {@code [0, q)} (up to a negligible statistical distance). */
    BigInteger next();

    /**
     * Called before the prover restarts with fresh nonces (spec §7.3). A deterministic source fails
     * closed here with an {@link IllegalStateException} (spec §7.5).
     */
    void beforeRestart();
}
