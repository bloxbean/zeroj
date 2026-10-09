package org.zeroj.circuit.lib.jubjub;

import java.util.Objects;

/**
 * A possession-verified key share of an n-of-n joint key ({@code elgamal-jubjub-v1} §3.3,
 * ADR-0052 D5 and invariant I2).
 *
 * <p>The only ways to obtain one are:
 * <ul>
 *   <li>{@link #verify}: a caller-supplied verifier accepted the possession statement
 *       {@code (X = G, P = D = key)} that the library built;</li>
 *   <li>{@link #fromSecret}: the key is computed locally from a held secret. Local knowledge of
 *       the discrete logarithm is possession.</li>
 * </ul>
 * {@link ElGamalPublicKey#aggregate} accepts nothing else, which blocks the rogue-key attack
 * ({@code PK_n = [x]·G − Σ PK_j} cannot be proved).
 */
public final class VerifiedKeyShare {

    private final ElGamalPublicKey publicKey;

    private VerifiedKeyShare(ElGamalPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Verifies possession of a key received as bytes.
     *
     * @throws IllegalArgumentException if the bytes are not a canonical, non-identity subgroup
     *         point (spec §7.3), or if the verifier rejects the possession statement
     */
    public static VerifiedKeyShare verify(byte[] encodedKey, DleqStatementVerifier verifier) {
        JubjubPoint candidate = ElGamalEncodings.decodeSubgroupPoint(encodedKey, "key share");
        return verify(candidate, verifier);
    }

    /**
     * Verifies possession of a key received as a point.
     *
     * @throws IllegalArgumentException if the point is the identity or outside the subgroup, or
     *         if the verifier rejects the possession statement
     */
    public static VerifiedKeyShare verify(JubjubPoint candidate, DleqStatementVerifier verifier) {
        Objects.requireNonNull(verifier, "verifier");
        JubjubPoint key = ElGamalEncodings.requireKeyPoint(candidate, "key share");
        if (!verifier.verify(DleqStatement.possession(key))) {
            throw new IllegalArgumentException("proof of possession rejected for key share");
        }
        return new VerifiedKeyShare(new ElGamalPublicKey(key));
    }

    /** A share whose secret this party holds. */
    public static VerifiedKeyShare fromSecret(ElGamalSecretKey secretKey) {
        Objects.requireNonNull(secretKey, "secretKey");
        return new VerifiedKeyShare(secretKey.publicKey());
    }

    /** The share's public key. */
    public ElGamalPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public String toString() {
        return "VerifiedKeyShare{" + publicKey + "}";
    }
}
