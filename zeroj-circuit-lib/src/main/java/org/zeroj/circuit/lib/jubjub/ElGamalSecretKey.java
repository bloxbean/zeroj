package org.zeroj.circuit.lib.jubjub;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;

import static org.zeroj.circuit.lib.jubjub.JubjubCurve.SUBGROUP_ORDER;

/**
 * An {@code elgamal-jubjub-v1} secret key {@code sk ∈ [1, l)} together with its public key
 * {@code [sk]·G} (spec §3.1). It serves as a single key, or as one trustee's share of an n-of-n
 * joint key (§3.2).
 *
 * <p><b>Compatibility/offline class (ADR-0039 §3.1).</b> Key generation and every operation
 * that multiplies by {@code sk} run variable-time {@link BigInteger} arithmetic through the
 * blinded best-effort schedule. Generate and use keys offline or in an isolated process. No
 * method of this class makes a constant-time claim. The secret cannot be wiped from memory:
 * {@code BigInteger} copies are immutable.
 */
public final class ElGamalSecretKey {

    private final BigInteger secret;
    private final ElGamalPublicKey publicKey;

    private ElGamalSecretKey(BigInteger secret, JubjubPoint publicKey) {
        this.secret = secret;
        this.publicKey = new ElGamalPublicKey(publicKey);
    }

    /**
     * Samples a key: 64 random bytes reduced mod {@code l}, resampled while zero (spec §2).
     *
     * @param random a cryptographically secure source
     */
    public static ElGamalSecretKey generate(SecureRandom random) {
        Objects.requireNonNull(random, "random");
        while (true) {
            BigInteger candidate = ElGamal.sample(random);
            if (candidate.signum() != 0) {
                return of(candidate);
            }
        }
    }

    /**
     * Wraps an existing secret.
     *
     * @throws IllegalArgumentException unless {@code 1 ≤ sk < l}
     */
    public static ElGamalSecretKey of(BigInteger sk) {
        Objects.requireNonNull(sk, "sk");
        if (sk.signum() <= 0 || sk.compareTo(SUBGROUP_ORDER) >= 0) {
            throw new IllegalArgumentException("secret key must satisfy 1 <= sk < l");
        }
        JubjubPoint pk = JubjubPoint.SUBGROUP_GENERATOR.scalarMulSecretBlindedBestEffort(sk).normalized();
        return new ElGamalSecretKey(sk, pk);
    }

    /** The public key {@code [sk]·G}. */
    public ElGamalPublicKey publicKey() {
        return publicKey;
    }

    /**
     * The proof-of-possession statement for this key (spec §3.3, §9.2): {@code X = G},
     * {@code P = D = [sk]·G}. A trustee proves it with {@code sk} as the witness; others check
     * it through {@link VerifiedKeyShare#verify}.
     */
    public DleqStatement possessionStatement() {
        return DleqStatement.possession(publicKey.point());
    }

    /**
     * The secret scalar, for building a proof witness only: the DLEQ relation of a possession
     * or decryption-share proof takes {@code sk} as its witness (spec §9.2).
     *
     * <p><b>Secret.</b> Handle it offline or in an isolated process (ADR-0039
     * compatibility/offline class). Do not decrypt with it through raw primitives
     * ({@link JubjubPoint#scalarMul}, {@link RawElGamalCiphertext#unmask},
     * {@link JubjubDiscreteLog#solve}). That gives up the safe layer's checks: the established
     * bound, the key context, and the subgroup check on the handle (multiplying an unvalidated
     * point by {@code sk} leaks {@code sk mod 8}). It also gives up the blinded multiplication
     * schedule. Every other use goes through this class's methods and {@link ElGamal}.
     */
    public BigInteger secretScalar() {
        return secret;
    }

    /** {@code [sk]·P} for a point known to be in the prime-order subgroup. */
    JubjubPoint multiply(JubjubPoint subgroupPoint) {
        return subgroupPoint.scalarMulSecretBlindedBestEffort(secret);
    }

    @Override
    public String toString() {
        return "ElGamalSecretKey{publicKey=" + publicKey + ", secret=<redacted>}";
    }
}
